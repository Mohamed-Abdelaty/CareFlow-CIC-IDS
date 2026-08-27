FROM apache/spark:3.5.3

USER root
ENV PATH="/opt/spark/bin:${PATH}"

# Pre-download Kafka + PostgreSQL JDBC connectors at build time
RUN /opt/spark/bin/spark-shell \
    --packages "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0,org.postgresql:postgresql:42.7.3" \
    < /dev/null 2>&1 | tail -5 || true

# Install Python dependencies for inference UDF and Postgres writes
RUN pip install --no-cache-dir pyarrow==16.0.0 numpy psycopg2-binary

WORKDIR /opt/jobs
COPY jobs/ /opt/jobs/

# Default command: run the unified streaming processor with Kafka + Postgres packages.
CMD ["/opt/spark/bin/spark-submit", \
     "--packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0,org.postgresql:postgresql:42.7.3", \
     "--master", "spark://spark-master:7077", \
     "--conf", "spark.executor.memory=2g", \
     "--conf", "spark.driver.memory=2g", \
     "--conf", "spark.memory.fraction=0.8", \
     "/opt/jobs/process_stream.py"]
