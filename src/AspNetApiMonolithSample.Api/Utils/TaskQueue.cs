using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api.Utils
{
    // This utility is MIT licensed, original code can be found from:
    // https://github.com/Ciantic/TaskQueue
    public class TaskQueue
    {
        private readonly ConcurrentQueue<Func<Task>> _processingQueue = new ConcurrentQueue<Func<Task>>();
        private readonly ConcurrentDictionary<int, Task> _runningTasks = new ConcurrentDictionary<int, Task>();
        private readonly int _maxParallelizationCount;
        private readonly int _maxQueueLength;
        private TaskCompletionSource<bool> _tscQueue = new TaskCompletionSource<bool>();

        public TaskQueue(int? maxParallelizationCount = null, int? maxQueueLength = null)
        {
            _maxParallelizationCount = maxParallelizationCount ?? int.MaxValue;
            _maxQueueLength = maxQueueLength ?? int.MaxValue;
        }

        public bool Queue(Func<Task> futureTask)
        {
            if (_processingQueue.Count < _maxQueueLength)
            {
                _processingQueue.Enqueue(futureTask);
                return true;
            }
            return false;
        }

        public int GetQueueCount()
        {
            return _processingQueue.Count;
        }

        public int GetRunningCount()
        {
            return _runningTasks.Count;
        }

        public async Task Process()
        {
            var t = _tscQueue.Task;
            StartTasks();
            await t;
        }

        public void ProcessBackground(Action<Exception> exception = null)
        {
            Task.Run(Process).ContinueWith(t => {
                exception?.Invoke(t.Exception);
            }, TaskContinuationOptions.OnlyOnFaulted);
        }

        private void StartTasks()
        {
            var startMaxCount = _maxParallelizationCount - _runningTasks.Count;
            for (int i = 0; i < startMaxCount; i++)
            {
                Func<Task> futureTask;
                if (!_processingQueue.TryDequeue(out futureTask))
                {
                    // Queue is most likely empty
                    break;
                }

                var t = Task.Run(futureTask);
                if (!_runningTasks.TryAdd(t.GetHashCode(), t))
                {
                    throw new Exception("Should not happen, hash codes are unique");
                }

                t.ContinueWith((t2) =>
                {
                    Task _temp;
                    if (!_runningTasks.TryRemove(t2.GetHashCode(), out _temp))
                    {
                        throw new Exception("Should not happen, hash codes are unique");
                    }

                    // Continue the queue processing
                    StartTasks();
                });
            }

            if (_processingQueue.IsEmpty && _runningTasks.IsEmpty)
            {
                // Interlocked.Exchange might not be necessary
                var _oldQueue = Interlocked.Exchange(
                    ref _tscQueue, new TaskCompletionSource<bool>());
                _oldQueue.TrySetResult(true);
            }
        }
    }

}
