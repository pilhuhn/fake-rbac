
from kafka import KafkaConsumer, KafkaProducer
from kafka.consumer.fetcher import ConsumerRecord
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (BatchSpanProcessor)
from opentelemetry.trace import SpanContext, TraceFlags, NonRecordingSpan

import logging
import random
import re
import time


# RE to process the incoming header. Taken from
#    opentelemetry.propagators.textmap.TextMapPropagator
_TRACEPARENT_HEADER_FORMAT = (
        "^[ \t]*([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})"
        + "(-.*)?[ \t]*$"
    )
_TRACEPARENT_HEADER_FORMAT_RE = re.compile(_TRACEPARENT_HEADER_FORMAT)


def extract_trace_data(parent_data):
    """Extracts the data from the 'traceparent' header value (passed in)
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


def get_trace_parent_header(message: ConsumerRecord):
    """
    Find the traceparent header in the list of available
    Kafka header fields. The header itself is a Tuple,
    from where we only return the value.
    """

    for header in message.headers:
        key = header[0]
        if key == 'traceparent':
            val = header[1]
            return val.decode('utf-8')

    return None


if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)
    random.seed(time.time_ns())

    from opentelemetry.instrumentation.kafka import KafkaInstrumentor
    KafkaInstrumentor().instrument()

    # Set up exporting
    resource = Resource(attributes={
        SERVICE_NAME: "kafka-relay"
    })
    # Configure the provider with the service name
    provider = TracerProvider(resource=resource)
    # We need to provide the /v1/traces part when we use the http-exporter on port 4318
    # For the grpc endpoint on port 4317, this is not needed.
    processor = BatchSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4317"))
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    tracer = trace.get_tracer('kaf-relay')

    consumer = KafkaConsumer('topic1')
    producer = KafkaProducer()

    # Loop over incoming messages, process then and
    # forward to topic2
    for msg in consumer:
        print(msg)

        # We need to explicitly extract the SpanContext from the incoming
        # Message in order to set it as parent context
        trace_parent = get_trace_parent_header(msg)
        span_context = extract_trace_data(trace_parent)
        ctx = trace.set_span_in_context(NonRecordingSpan(span_context))

        with tracer.start_as_current_span("do-the-work-span", context=ctx) as span:
            # do the work
            body = msg.value.decode('utf-8')
            body = body + '  from Python'
            # and send it off to topic2
            producer.send('topic2', body.encode('utf-8'))

