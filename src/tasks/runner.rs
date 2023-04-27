use tokio::runtime::Handle;
use tokio::time;

pub struct TaskRunner {
    handle: Handle,
}

impl TaskRunner {
    pub fn new() -> Self {
        TaskRunner {
            handle: Handle::current(),
        }
    }

    pub fn run_task<F, R>(&self, interval: time::Duration, mut task: F)
    where
        F: FnMut() -> R + Send + 'static,
        R: std::future::Future<Output = ()> + Send + 'static,
    {
        let handle = self.handle.clone();
        let future = async move {
            let mut interval = time::interval(interval);
            loop {
                interval.tick().await;
                let task_future = task();
                handle.spawn(async move {
                    task_future.await;
                });
            }
        };

        self.handle.spawn(future);
    }
}
