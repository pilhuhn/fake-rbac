from http.server import BaseHTTPRequestHandler, HTTPServer

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
# from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (BatchSpanProcessor, ConsoleSpanExporter)
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.instrumentation.requests import RequestsInstrumentor

import logging
import random
import requests
import re
import time


# RE to process the incoming header. Taken from
#    opentelemetry.propagators.textmap.TextMapPropagator
_TRACEPARENT_HEADER_FORMAT = (
        "^[ \t]*([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})"
        + "(-.*)?[ \t]*$"
    )
_TRACEPARENT_HEADER_FORMAT_RE = re.compile(_TRACEPARENT_HEADER_FORMAT)

# Our reply body to the client
reply = '{"meta":{"count":1,"limit":1,"offset":0},' \
        '"links":{"first":"/api/rbac/v1/access/?application=policies&limit=1&offset=0",' \
        '"next":null,"previous":null,' \
        '"last":"/api/rbac/v1/access/?application=policies&limit=1&offset=0"},' \
        '"data":[{"resourceDefinitions":[],"permission":"policies:*:*"}]}'


def extract_trace_data(parent_data):
    """Extracts the data from the 'traceparent' http header value (passed in)
    and creates a new SpanContext object from it that is then returned
    """
    match = re.search(_TRACEPARENT_HEADER_FORMAT_RE, parent_data)
    if not match:
        return None

    version: str = match.group(1)
    trace_id: str = match.group(2)
    span_id: str = match.group(3)
    trace_flags: str = match.group(4)

    span_context = SpanContext(
        trace_id=int(trace_id, 16),
        span_id=int(span_id, 16),
        is_remote=True,
        trace_flags=TraceFlags(0x01)
    )
    return span_context


class MyRequestHandler(BaseHTTPRequestHandler):
    """HttpServer request handler for illustration purposes"""

    def do_GET(self):
        # We need to extract the parent trace+span from the incoming request
        # and if it is there, provide it as context
        inc_trace = self.headers["traceparent"]
        ctx = {}
        span_context = None
        if inc_trace is not None:
            print(inc_trace)
            span_context = extract_trace_data(inc_trace)
            ctx = trace.set_span_in_context(NonRecordingSpan(span_context))
        with tracer.start_as_current_span("do-get-span", context=ctx) as span:
            if span_context is not None:
                s_ctx = span_context.trace_id
            else:
                s_ctx = 0
            logging.info("GET %s  traceId=%x", self.path, s_ctx)
            self.send_response(200)
            # simulate a failure every one and then
            if random.randint(0, 10) > 2:
                self.send_header("Content-Type", "application/json")
                span.set_attribute("type", "json")
                # No failure, but slowness
                if random.randint(0, 10) > 7:
                    time.sleep(1.5)
                    span.set_attribute("delayed", "true")

                # Call another service
                requests.put("http://localhost:8084/lightweight-engine/validate")
            else:
                # This will provoke an error in the caller as it only allows application/json
                self.send_header("Content_Type", "text/plain")
                span.set_attribute("type", "plain")
            self.end_headers()
            self.wfile.write(bytes(reply, "utf-8"))


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    random.seed(time.time_ns())

    # Instrument the requests library
    RequestsInstrumentor().instrument()

    # Set up exporting
    resource = Resource(attributes={
        SERVICE_NAME: "fake-rbac"
    })
    # Configure the provider with the service name
    provider = TracerProvider(resource=resource)
    # We need to provide the /v1/traces part when we use the http-exporter on port 4318
    # For the grpc endpoint on port 4317, this is not needed.
    processor = BatchSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4317"))
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    tracer = trace.get_tracer(__name__)

    server = HTTPServer(("localhost", 8787), MyRequestHandler)
    print("Server started on port 8787")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("Server stopped.")
