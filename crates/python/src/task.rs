//! Work running on a thread of its own, which never takes the GIL

use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use frinet_db::{calltree::Calltree, search::SearchMatch, task::Task};
use pyo3::{
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
};

use crate::{
    calltree::PyCalltree,
    error::{Cancelled, NativeError, panic_message},
    search::PySearchMatches,
};

/// How long a wait blocks before looking for a signal, short enough to feel a Ctrl-C
const WAIT_SLICE: Duration = Duration::from_millis(50);

/// What a task hands back once it ends well
pub enum Output {
    Nothing,
    Matches(Vec<SearchMatch>),
    Tree(Calltree),
}

/// Why a task hands back nothing
pub enum Failure {
    Cancelled,
    Error(String),
}

enum State {
    Running,
    Ended(Result<Output, Failure>),
    Read,
}

struct Shared {
    task: Task,
    state: Mutex<State>,
    ended: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("a poisoned lock needs a panic")
    }

    fn is_running(&self) -> bool {
        matches!(*self.lock(), State::Running)
    }

    fn wait(&self, timeout: Duration) -> bool {
        let running = |state: &mut State| matches!(state, State::Running);
        let (_guard, result) = self
            .ended
            .wait_timeout_while(self.lock(), timeout, running)
            .expect("a poisoned lock needs a panic");
        !result.timed_out()
    }
}

/// Runs `work` on a thread of its own, turning a panic into the error of the task
pub fn spawn(work: impl FnOnce(&Task) -> Result<Output, Failure> + Send + 'static) -> PyTask {
    let shared = Arc::new(Shared {
        task: Task::new(),
        state: Mutex::new(State::Running),
        ended: Condvar::new(),
    });
    let thread_shared = Arc::clone(&shared);

    std::thread::spawn(move || {
        let output = panic::catch_unwind(AssertUnwindSafe(|| work(&thread_shared.task)))
            .unwrap_or_else(|payload| Err(Failure::Error(panic_message(&*payload).to_owned())));
        *thread_shared.lock() = State::Ended(output);
        thread_shared.ended.notify_all();
    });

    PyTask(shared)
}

/// Handle on work running on a Rust thread, see [crate::search::search_start]
#[pyclass(name = "Task", frozen)]
pub struct PyTask(Arc<Shared>);

#[pymethods]
impl PyTask {
    /// How much of the work is done, from 0 to 1
    fn progress(&self) -> f64 {
        if matches!(*self.0.lock(), State::Ended(Ok(_)) | State::Read) {
            return 1.0;
        }
        match self.0.task.progress() {
            (_, 0) => 0.0,
            (done, total) => (done as f64 / total as f64).min(1.0),
        }
    }

    fn is_done(&self) -> bool {
        !self.0.is_running()
    }

    /// Asks the work to stop, it then raises [Cancelled] instead of handing back a result
    fn cancel(&self) {
        self.0.task.cancel();
    }

    #[pyo3(signature = (timeout = None))]
    fn wait(&self, py: Python<'_>, timeout: Option<f64>) -> PyResult<bool> {
        let timeout = match timeout {
            None => None,
            Some(seconds) if seconds.is_nan() || seconds < 0.0 => {
                let message = format!("{seconds} is not a number of seconds to wait");
                return Err(PyValueError::new_err(message));
            }
            // longer than a `Duration` is as good as a wait without a timeout
            Some(seconds) => Some(Duration::try_from_secs_f64(seconds).unwrap_or(Duration::MAX)),
        };
        let start = Instant::now();

        loop {
            let slice = match timeout {
                None => WAIT_SLICE,
                Some(timeout) => {
                    let left = timeout.saturating_sub(start.elapsed());
                    if left.is_zero() {
                        return Ok(!self.0.is_running());
                    }
                    left.min(WAIT_SLICE)
                }
            };

            if py.detach(|| self.0.wait(slice)) {
                return Ok(true);
            }
            py.check_signals()?;
        }
    }

    /// The result of the ended work, read once, raising what the work raised
    fn take(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let mut guard = self.0.lock();
        let output = match &*guard {
            State::Running => return Err(PyRuntimeError::new_err("the work is still running")),
            State::Read => return Err(PyRuntimeError::new_err("the result was already read")),
            State::Ended(Err(Failure::Cancelled)) => {
                return Err(Cancelled::new_err("the work was cancelled"));
            }
            State::Ended(Err(Failure::Error(message))) => {
                return Err(NativeError::new_err(message.clone()));
            }
            State::Ended(Ok(_)) => match std::mem::replace(&mut *guard, State::Read) {
                State::Ended(Ok(output)) => output,
                _ => unreachable!(),
            },
        };
        drop(guard);

        Ok(match output {
            Output::Nothing => py.None(),
            Output::Matches(matches) => PySearchMatches::new(matches)
                .into_pyobject(py)?
                .into_any()
                .unbind(),
            Output::Tree(tree) => PyCalltree(tree).into_pyobject(py)?.into_any().unbind(),
        })
    }
}
