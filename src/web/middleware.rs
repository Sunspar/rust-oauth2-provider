use iron::prelude::*;
use iron::middleware::AfterMiddleware;
use iron;
use iron::headers::{ContentType, Pragma, CacheControl, CacheDirective};
use hyper::mime::{Mime, TopLevel, SubLevel, Attr, Value};
use web::headers::WWWAuthenticate;

pub struct AttachGeneralOAuth2Headers;
impl AfterMiddleware for AttachGeneralOAuth2Headers {
	fn after(&self, _req: &mut Request, res: Response) -> IronResult<Response> {
		let mut res = res;
		res.headers.set(Pragma::NoCache);
		res.headers.set(CacheControl(vec![CacheDirective::NoStore]));
		res.headers.set(ContentType(Mime(TopLevel::Application, SubLevel::Json, vec![(Attr::Charset, Value::Utf8)])));

		if res.status == Some(iron::status::Unauthorized) {
			res.headers.set(WWWAuthenticate("Basic".to_owned()));
		};

		Ok(res)
	}

	fn catch(&self, _req: &mut Request, err: IronError) -> IronResult<Response> {
		Err(err)
	}
}