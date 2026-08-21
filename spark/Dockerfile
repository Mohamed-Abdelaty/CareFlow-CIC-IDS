FROM apache/spark:3.5.3

USER root
ENV PATH="/opt/spark/bin:${PATH}"

# Download Kafka connector JAR at build time
RUN /opt/spark/bin/spark-shell --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0 < /dev/null 2>&1 | tail -5 || true

WORKDIR /opt/jobs
COPY jobs/ /opt/jobs/

CMD ["/opt/spark/bin/spark-submit", \
     "--packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0", \
     "--master", "spark://spark-master:7077", \
     "/opt/jobs/process_stream.py"]
