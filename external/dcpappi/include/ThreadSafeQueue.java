package dpi;

import java.util.*;
import java.util.concurrent.locks.*;

public final class ThreadSafeQueue<T> {
    private final int maxSize;
    private final Deque<T> queue = new ArrayDeque<>();
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty=lock.newCondition(), notFull=lock.newCondition();
    private boolean shutdown;
    public ThreadSafeQueue() { this(10000); }
    public ThreadSafeQueue(int maxSize) { if(maxSize<1) throw new IllegalArgumentException("maxSize must be positive"); this.maxSize=maxSize; }
    public void push(T item) throws InterruptedException {
        lock.lockInterruptibly();
        try { while(queue.size()>=maxSize && !shutdown) notFull.await(); if(shutdown)return; queue.addLast(item); notEmpty.signal(); }
        finally { lock.unlock(); }
    }
    public boolean tryPush(T item) {
        lock.lock();
        try { if(shutdown || queue.size()>=maxSize)return false; queue.addLast(item); notEmpty.signal(); return true; }
        finally { lock.unlock(); }
    }
    public Optional<T> pop() throws InterruptedException {
        lock.lockInterruptibly();
        try { while(queue.isEmpty()&&!shutdown)notEmpty.await(); if(queue.isEmpty())return Optional.empty(); T v=queue.removeFirst();notFull.signal();return Optional.of(v); }
        finally {lock.unlock();}
    }
    public Optional<T> popWithTimeout(long millis) throws InterruptedException {
        long nanos=java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(millis);
        lock.lockInterruptibly();
        try { while(queue.isEmpty()&&!shutdown&&nanos>0)nanos=notEmpty.awaitNanos(nanos); if(queue.isEmpty())return Optional.empty();T v=queue.removeFirst();notFull.signal();return Optional.of(v); }
        finally {lock.unlock();}
    }
    public boolean isEmpty(){lock.lock();try{return queue.isEmpty();}finally{lock.unlock();}}
    public int size(){lock.lock();try{return queue.size();}finally{lock.unlock();}}
    public void shutdown(){lock.lock();try{shutdown=true;notEmpty.signalAll();notFull.signalAll();}finally{lock.unlock();}}
    public boolean isShutdown(){lock.lock();try{return shutdown;}finally{lock.unlock();}}
}
