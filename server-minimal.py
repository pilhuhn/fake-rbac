from http.server import BaseHTTPRequestHandler, HTTPServer

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (BatchSpanProcessor)

import random
import time


reply = '{"meta":{"count":1,"limit":1,"offset":0},' \
        '"links":{"first":"/api/rbac/v1/access/?application=policies&limit=1&offset=0",' \
        '"next":null,"previous":null,' \
        '"last":"/api/rbac/v1/access/?application=policies&limit=1&offset=0"},' \
        '"data":[{"resourceDefinitions":[],"permission":"policies:*:*"}]}'


class MyRequestHandler(BaseHTTPRequestHandler):
    """HttpServer request handler for illustration purposes"""

    def do_GET(self):
        with tracer.start_as_current_span("do-get-span") as span:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            span.set_attribute("type", "json")
            # Simulate random slowness
            if random.randint(0, 10) > 7:
                time.sleep(1.5)
                span.set_attribute("delayed", "true")
            self.end_headers()
            self.wfile.write(bytes(reply, "utf-8"))


if __name__ == "__main__":

    # Set up exporting
    resource = Resource(attributes={
        SERVICE_NAME: "fake-rbac"
    })
    # Configure the provider with the service name
    provider = TracerProvider(resource=resource)
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
