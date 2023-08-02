package com.tangerine.springsecuritymasterclass;

import java.util.concurrent.CompletableFuture;

public class ThreadLocalApp {

    final static ThreadLocal<Integer> threadLocalValue = new ThreadLocal<>();

    public static void main(String[] args) {
        System.out.println(getCurrentThreadName() + " ### main set value = 1");
        threadLocalValue.set(1);

        // 하나의 Thread 를 공유
        // 따라서 같은 값 반환
        a();
        b();

        // runAsync : 다른 Thread 에서 실행
        // 다른 Thread 의 변수에는 접근할 수 없으므로, null 이 출력
        CompletableFuture.runAsync(() -> {
            a();
            b();
        }).join();
    }

    public static void a() {
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### a() get value = " + value);
    }

    public static void b() {
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### b() get value = " + value);
    }

    public static String getCurrentThreadName() {
        return Thread.currentThread().getName();
    }

}
