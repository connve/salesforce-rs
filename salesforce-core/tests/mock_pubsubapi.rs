//! Offline tests for the Pub/Sub API streaming methods.
//!
//! Runs against an in-process echo server and needs no Salesforce org, so it
//! isn't `#[ignore]`d.

use salesforce_core::client;
use salesforce_core::pubsubapi::pub_sub_server::{PubSub, PubSubServer};
use salesforce_core::pubsubapi::{
    Client, CommitReplayRequest, CommitReplayResponse, FetchRequest, FetchResponse,
    ManagedFetchRequest, ManagedFetchResponse, PublishRequest, PublishResponse, SchemaInfo,
    SchemaRequest, TopicInfo, TopicRequest,
};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status, Streaming};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

type EchoStream<T> = ReceiverStream<std::result::Result<T, Status>>;

/// Reads responses until the stream ends, or fails after 5 seconds.
async fn collect<T>(mut stream: Streaming<T>) -> Result<Vec<T>> {
    let read_all = async {
        let mut responses = Vec::new();
        while let Some(response) = stream.message().await? {
            responses.push(response);
        }
        Ok::<_, Status>(responses)
    };
    Ok(tokio::time::timeout(std::time::Duration::from_secs(5), read_all).await??)
}

/// Answers each request with `respond(request)`.
fn echo<Req, Resp>(mut inbound: Streaming<Req>, respond: fn(Req) -> Resp) -> EchoStream<Resp>
where
    Req: Send + 'static,
    Resp: Send + 'static,
{
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let item = match inbound.message().await {
                Ok(Some(request)) => Ok(respond(request)),
                Ok(None) => break,
                Err(status) => Err(status),
            };
            if tx.send(item).await.is_err() {
                break;
            }
        }
    });
    ReceiverStream::new(rx)
}

struct EchoServer;

#[tonic::async_trait]
impl PubSub for EchoServer {
    type SubscribeStream = EchoStream<FetchResponse>;
    type PublishStreamStream = EchoStream<PublishResponse>;
    type ManagedSubscribeStream = EchoStream<ManagedFetchResponse>;

    async fn subscribe(
        &self,
        request: Request<Streaming<FetchRequest>>,
    ) -> std::result::Result<Response<Self::SubscribeStream>, Status> {
        Ok(Response::new(echo(request.into_inner(), |r| {
            FetchResponse {
                rpc_id: r.topic_name,
                pending_num_requested: r.num_requested,
                ..Default::default()
            }
        })))
    }

    async fn managed_subscribe(
        &self,
        request: Request<Streaming<ManagedFetchRequest>>,
    ) -> std::result::Result<Response<Self::ManagedSubscribeStream>, Status> {
        Ok(Response::new(echo(request.into_inner(), |r| {
            ManagedFetchResponse {
                rpc_id: r.developer_name,
                pending_num_requested: r.num_requested,
                commit_response: r.commit_replay_id_request.map(|c| CommitReplayResponse {
                    commit_request_id: c.commit_request_id,
                    replay_id: c.replay_id,
                    ..Default::default()
                }),
                ..Default::default()
            }
        })))
    }

    async fn publish_stream(
        &self,
        request: Request<Streaming<PublishRequest>>,
    ) -> std::result::Result<Response<Self::PublishStreamStream>, Status> {
        Ok(Response::new(echo(request.into_inner(), |r| {
            PublishResponse {
                rpc_id: r.topic_name,
                ..Default::default()
            }
        })))
    }

    async fn get_schema(
        &self,
        _: Request<SchemaRequest>,
    ) -> std::result::Result<Response<SchemaInfo>, Status> {
        Err(Status::unimplemented("get_schema"))
    }

    async fn get_topic(
        &self,
        _: Request<TopicRequest>,
    ) -> std::result::Result<Response<TopicInfo>, Status> {
        Err(Status::unimplemented("get_topic"))
    }

    async fn publish(
        &self,
        _: Request<PublishRequest>,
    ) -> std::result::Result<Response<PublishResponse>, Status> {
        Err(Status::unimplemented("publish"))
    }
}

/// Starts the echo server and connects a client to it.
async fn pubsub_client() -> Result<Client> {
    let oauth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "fake-token",
            "token_type": "Bearer",
        })))
        .mount(&oauth)
        .await;
    let auth = client::Client::builder()
        .client_id("id")
        .client_secret("secret")
        .instance_url(oauth.uri())
        .tenant_id("tenant")
        .build()?
        .connect()
        .await?;

    let incoming = TcpIncoming::bind("127.0.0.1:0".parse()?)?;
    let addr = incoming.local_addr()?;
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(PubSubServer::new(EchoServer))
            .serve_with_incoming(incoming),
    );

    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))?
        .connect()
        .await?;
    Ok(Client::new(channel, auth)?)
}

#[tokio::test]
async fn subscribe_sends_each_request_once() -> Result {
    let mut client = pubsub_client().await?;
    let (tx, rx) = mpsc::channel(4);
    tx.send(FetchRequest {
        topic_name: "/event/Test__e".to_string(),
        num_requested: 5,
        ..Default::default()
    })
    .await?;
    tx.send(FetchRequest {
        num_requested: 7,
        ..Default::default()
    })
    .await?;
    drop(tx);

    let responses: Vec<_> = collect(client.subscribe(rx).await?.into_inner())
        .await?
        .into_iter()
        .map(|r| (r.rpc_id, r.pending_num_requested))
        .collect();

    assert_eq!(
        responses,
        [("/event/Test__e".to_string(), 5), (String::new(), 7)]
    );
    Ok(())
}

#[tokio::test]
async fn managed_subscribe_sends_fetch_and_commit_requests() -> Result {
    let mut client = pubsub_client().await?;
    let (tx, rx) = mpsc::channel(4);
    tx.send(ManagedFetchRequest {
        developer_name: "Managed_Sub".to_string(),
        num_requested: 5,
        ..Default::default()
    })
    .await?;
    tx.send(ManagedFetchRequest {
        commit_replay_id_request: Some(CommitReplayRequest {
            commit_request_id: "1".to_string(),
            replay_id: b"replay-1".to_vec(),
        }),
        ..Default::default()
    })
    .await?;
    drop(tx);

    let responses = collect(client.managed_subscribe(rx).await?.into_inner()).await?;

    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].rpc_id, "Managed_Sub");
    assert_eq!(responses[0].pending_num_requested, 5);
    assert!(responses[0].commit_response.is_none());
    let commit = responses[1]
        .commit_response
        .as_ref()
        .ok_or("missing commit response")?;
    assert_eq!(commit.commit_request_id, "1");
    assert_eq!(commit.replay_id, b"replay-1");
    Ok(())
}

#[tokio::test]
async fn publish_stream_publishes_each_request_once() -> Result {
    let mut client = pubsub_client().await?;
    let (tx, rx) = mpsc::channel(4);
    for topic in ["/event/A__e", "/event/B__e"] {
        tx.send(PublishRequest {
            topic_name: topic.to_string(),
            ..Default::default()
        })
        .await?;
    }
    drop(tx);

    let topics: Vec<_> = collect(client.publish_stream(rx).await?.into_inner())
        .await?
        .into_iter()
        .map(|r| r.rpc_id)
        .collect();

    assert_eq!(topics, ["/event/A__e", "/event/B__e"]);
    Ok(())
}
