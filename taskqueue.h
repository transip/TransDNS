#pragma once

#include <condition_variable>
#include <mutex>
#include <queue>

template <class T>
class TaskQueue {
private:
    std::queue<T> taskQueue;
    std::mutex queueMutex;
    std::condition_variable conditionVar;

public:
    void write(T value)
    {
        std::unique_lock<std::mutex> lock(this->queueMutex);
        this->taskQueue.push(value);
        this->conditionVar.notify_one();
        lock.unlock();
    }

    T read()
    {
        std::unique_lock<std::mutex> lock(this->queueMutex);

        while (true) {
            if (!this->taskQueue.empty()) {
                T value = this->taskQueue.front();
                this->taskQueue.pop();
                lock.unlock();
                return value;
            }

            this->conditionVar.wait(lock);
        }
    }
};
