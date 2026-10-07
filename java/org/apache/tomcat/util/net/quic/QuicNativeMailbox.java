/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.net.quic;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Consumer;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.res.StringManager;

/**
 * Single owner of the work queue that crosses an endpoint's poll-thread
 * confinement boundary. QUIC connections are not thread-safe for concurrent
 * access, so every native operation runs on the poll thread; other threads
 * hand work to it through this queue:
 * <ul>
 * <li>{@code pollTasks}: generic tasks (worker native hops, self-requeuing
 * dispatch retries) drained on every poll iteration and during
 * shutdown.</li>
 * </ul>
 * <p>
 * The OpenSSL endpoint extends this class with its transport-specific
 * deferred and Cleaner stream-free queues
 * ({@code org.apache.tomcat.util.net.quic.openssl.QuicNativeMailbox}); the
 * quiche transport has no such queues because quiche streams carry no native
 * handle (the {@code quiche_conn} free itself is deferred in the endpoint's
 * own loop state).
 * <p>
 * The drain performs native work and must run on the poll thread (or on the
 * stop thread once the poll loop has stopped); a confinement check is applied
 * to each drain so a future mis-threading is caught under {@code -ea}.
 */
public class QuicNativeMailbox {

    private static final Log log = LogFactory.getLog(QuicNativeMailbox.class);
    private static final StringManager sm =
            StringManager.getManager(QuicNativeMailbox.class);

    private final ConcurrentLinkedQueue<Runnable> pollTasks =
            new ConcurrentLinkedQueue<>();

    /**
     * Set by {@link #close()} when the endpoint has finished stopping: tasks
     * submitted afterwards target connections that may already be freed, so
     * they are dropped instead of queued (they would otherwise linger in this
     * queue - it is reused across endpoint stop/start cycles - and run
     * against the freed connections on the next start).
     */
    private volatile boolean closed;

    /**
     * Guards the check-vs-act of {@link #submitPollTask} against
     * {@link #close()}: without it, a submission that checked {@code closed}
     * as {@code false} could add its task after the close's discard ran,
     * stranding the task (and anything it references) in the queue until the
     * next {@link #open()}. With the lock, a submission either completes
     * before the close (its task is then covered by the close's discard) or
     * observes {@code closed} and is rejected - nothing is ever stranded.
     */
    private final Object submitLock = new Object();

    /**
     * Applied at the start of every drain with the operation name; asserts
     * the poll-thread (or stopped-poll-thread) confinement invariant. Used
     * by the drains of subclasses too.
     */
    protected final Consumer<String> confinementCheck;

    /**
     * Wakes the poll thread after work is queued. May be {@code null} until
     * the endpoint has created its wake primitive; a queued task without a
     * kick is still executed on the next timed poll-loop iteration.
     */
    private volatile Runnable waker;


    /**
     * Creates the mailbox.
     *
     * @param confinementCheck applied at the start of every drain with the
     *                         operation name; asserts the poll-thread
     *                         (or stopped-poll-thread) confinement invariant
     */
    public QuicNativeMailbox(Consumer<String> confinementCheck) {
        this.confinementCheck = confinementCheck;
    }


    /**
     * Sets the callback used to wake the poll thread when work is queued
     * from another thread.
     *
     * @param waker The wake callback, or {@code null}
     */
    public void setWaker(Runnable waker) {
        this.waker = waker;
    }


    /**
     * Queues a task to run on the poll thread. The task must be a single fast
     * operation (one native call or one bookkeeping mutation) and must never
     * block, since the poll thread is the only thread that drains the queue.
     * <p>
     * Every submission kicks the endpoint's wake primitive so a task queued
     * while the poll thread waits in {@code poll(2)} is executed on the next
     * iteration instead of after the remaining wait timeout. The eventfd
     * counter is drained by the poll loop at the top of each iteration before
     * this queue, so a submission racing the drain cannot be lost: either the
     * drain takes the task or the kick still wakes the wait.
     *
     * @param task The task to run on the poll thread
     *
     * @return {@code true} if the task was queued, {@code false} if it was
     *         dropped because the mailbox is closed (endpoint stopped)
     */
    public boolean submitPollTask(Runnable task) {
        // The closed check and the add are atomic against close() (see
        // submitLock): the waker callback runs outside the lock so a slow
        // kick never serializes submissions.
        synchronized (submitLock) {
            if (closed) {
                return false;
            }
            pollTasks.add(task);
        }
        Runnable w = waker;
        if (w != null) {
            w.run();
        }
        return true;
    }


    /**
     * Closes the mailbox at the end of the endpoint stop: queued tasks are
     * discarded (their target connections are freed by the stop path) and
     * later submissions are rejected until {@link #open()}.
     */
    public void close() {
        synchronized (submitLock) {
            closed = true;
        }
        // Safe to discard outside the lock: every add that happened while the
        // mailbox was open completed before this thread acquired submitLock to
        // set closed (submit holds submitLock across its add), so no submit
        // can add concurrently with this discard.
        discardPollTasks();
    }


    /**
     * Re-opens the mailbox for a new endpoint start, discarding anything a
     * racing stop-path submission may have left behind.
     */
    public void open() {
        discardPollTasks();
        closed = false;
    }


    /**
     * Drops all queued poll tasks without running them.
     */
    public void discardPollTasks() {
        pollTasks.clear();
    }


    /**
     * Reports whether any poll task is queued. The poll loop shortens its
     * wait while tasks are pending so a queued hop is picked up on the next
     * iteration rather than after a full interval.
     *
     * @return {@code true} if at least one poll task is queued
     */
    public boolean hasPollTasks() {
        return !pollTasks.isEmpty();
    }


    /**
     * Runs all queued poll tasks. Called at the top of every poll loop
     * iteration, BEFORE the socket read and per-connection processing, so
     * tasks that queue frames or free native objects take effect before the
     * next send/recv pass sees them.
     *
     * @return {@code true} if at least one task ran
     */
    public boolean drainPollTasks() {
        confinementCheck.accept("drainPollTasks");
        Runnable task;
        boolean ranAny = false;
        while ((task = pollTasks.poll()) != null) {
            ranAny = true;
            try {
                task.run();
            } catch (Throwable t) {
                ExceptionUtils.handleThrowable(t);
                log.warn(sm.getString("mailbox.pollTaskError"), t);
            }
        }
        return ranAny;
    }
}
