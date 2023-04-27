use actix::Arbiter;
use futures::StreamExt;
use tokio_stream::wrappers::IntervalStream;

pub struct TaskRunner {
    arbiter: Arbiter,
}

impl TaskRunner {
    pub fn create() -> Self {
        TaskRunner {
            arbiter: Arbiter::new(),
        }
    }

    pub fn execute<F, R>(&mut self, interval: std::time::Duration, mut task: F)
    where
        F: FnMut() -> R + Send + 'static,
        R: std::future::Future<Output = ()> + Send + 'static,
    {
        let future = IntervalStream::new(actix::clock::interval(interval))
            .for_each_concurrent(2, move |_| task());

        self.arbiter.spawn(future);
    }
}

impl Drop for TaskRunner {
    fn drop(&mut self) {
        self.arbiter.stop();
    }
}
