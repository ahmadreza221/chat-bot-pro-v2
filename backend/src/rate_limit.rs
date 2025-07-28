use axum::{body::Body, http::{Request, Response}, BoxError};
use governor::{clock::DefaultClock, state::keyed::DashMapStateStore, Quota, RateLimiter};
use std::{num::NonZeroU32, sync::Arc, task::{Context, Poll}};
use tower::{Layer, Service};
use std::net::IpAddr;

#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<RateLimiter<String, DashMapStateStore<String>, DefaultClock>>,
}

impl RateLimitLayer {
    pub fn new(permits: u32, per_sec: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(per_sec).unwrap()).allow_burst(NonZeroU32::new(permits).unwrap());
        Self {
            limiter: Arc::new(RateLimiter::keyed(quota)),
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    limiter: Arc<RateLimiter<String, DashMapStateStore<String>, DefaultClock>>,
}

impl<S> Service<Request<Body>> for RateLimitService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let ip = req
            .extensions()
            .get::<std::net::SocketAddr>()
            .map(|s| s.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let key = format!("{}:{}", ip, req.uri().path());
        if self.limiter.check_key(&key).is_err() {
            return Box::pin(async move {
                let mut resp = Response::new(Body::from("Too Many Requests"));
                *resp.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
                Ok(resp)
            });
        }
        self.inner.call(req)
    }
} 