"""
Spark Structured Streaming job
- Reads from Kafka topic 'patients_stream'
- Applies enhanced cleaning + feature engineering:
    1. Drops rows with missing critical fields
    2. Fills missing severity with 'Unknown'
    3. Casts numeric fields to Double
    4. Filters out logically impossible values (Outlier Removal)
    5. Normalizes text fields (lowercase + trim)
    6. Groups diagnosis into high-level medical categories
- Writes raw and processed data to HDFS as Parquet
"""

import os

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, lower, trim, when
from pyspark.sql.types import StringType, StructField, StructType

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
TOPIC = os.getenv("KAFKA_TOPIC", "patients_stream")
HDFS_URI = os.getenv("HDFS_URI", "hdfs://namenode:8020")
RAW_PATH = f"{HDFS_URI}/hospital/raw"
PROCESSED_PATH = f"{HDFS_URI}/hospital/processed"
CHECKPOINT_PATH = f"{HDFS_URI}/hospital/checkpoints"

PATIENT_SCHEMA = StructType(
    [
        StructField("age_group", StringType(), True),
        StructField("gender", StringType(), True),
        StructField("admission_type", StringType(), True),
        StructField("diagnosis", StringType(), True),
        StructField("severity", StringType(), True),
        StructField("risk_of_mortality", StringType(), True),
        StructField("length_of_stay", StringType(), True),
        StructField("total_charges", StringType(), True),
        StructField("hospital_county", StringType(), True),
    ]
)


def build_spark():
    return (
        SparkSession.builder.appName("HospitalPatientFlowStreaming")
        .config(
            "spark.jars.packages",
            "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0",
        )
        .config("spark.hadoop.fs.defaultFS", HDFS_URI)
        .getOrCreate()
    )


def main():
    spark = build_spark()
    spark.sparkContext.setLogLevel("WARN")

    raw_stream = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
        .option("subscribe", TOPIC)
        .option("startingOffsets", "earliest")
        .load()
    )

    parsed = raw_stream.select(
        from_json(col("value").cast("string"), PATIENT_SCHEMA).alias("data")
    ).select("data.*")

    # ---- Step 1: Drop rows missing critical fields ----
    cleaned = parsed.dropna(subset=["age_group", "admission_type"])

    # ---- Step 2: Fill missing severity with 'Unknown' ----
    cleaned = cleaned.withColumn(
        "severity",
        when(col("severity").isNull(), "Unknown").otherwise(col("severity")),
    )

    # ---- Step 3: Cast numeric fields ----
    cleaned = (
        cleaned
        .withColumn("length_of_stay", col("length_of_stay").cast("double"))
        .withColumn("total_charges", col("total_charges").cast("double"))
    )

    # ---- Step 4: Outlier Removal — filter out logically impossible values ----
    # A patient cannot have zero or negative stay days or negative charges
    cleaned = cleaned.filter(
        (col("length_of_stay") > 0) &
        (col("length_of_stay") < 365) &   # max 1 year stay
        (col("total_charges") > 0) &
        (col("total_charges") < 10_000_000)  # max $10M charge
    )

    # ---- Step 5: Text Normalization — lowercase + trim whitespace ----
    text_cols = ["gender", "admission_type", "severity", "risk_of_mortality", "age_group"]
    for c in text_cols:
        cleaned = cleaned.withColumn(c, lower(trim(col(c))))

    # ---- Step 6: Diagnosis Grouping — map hundreds of diagnoses into major categories ----
    diag = lower(col("diagnosis"))
    cleaned = cleaned.withColumn(
        "diagnosis",
        when(diag.contains("heart") | diag.contains("cardiac") | diag.contains("coronary") | diag.contains("cardio"), "Cardiology")
        .when(diag.contains("pneumonia") | diag.contains("asthma") | diag.contains("respiratory") | diag.contains("lung") | diag.contains("bronch"), "Respiratory")
        .when(diag.contains("diabetes") | diag.contains("obesity") | diag.contains("endocrine") | diag.contains("thyroid"), "Endocrine & Metabolic")
        .when(diag.contains("hip") | diag.contains("knee") | diag.contains("fracture") | diag.contains("joint") | diag.contains("spine") | diag.contains("bone"), "Musculoskeletal")
        .when(diag.contains("kidney") | diag.contains("renal") | diag.contains("urinary") | diag.contains("bladder"), "Renal & Urinary")
        .when(diag.contains("cancer") | diag.contains("tumor") | diag.contains("lymphoma") | diag.contains("leukemia") | diag.contains("neoplasm"), "Oncology")
        .when(diag.contains("stroke") | diag.contains("neuro") | diag.contains("brain") | diag.contains("seizure") | diag.contains("epilep"), "Neurology")
        .when(diag.contains("depress") | diag.contains("anxiety") | diag.contains("psych") | diag.contains("schizo") | diag.contains("bipolar"), "Mental Health")
        .when(diag.contains("septic") | diag.contains("infection") | diag.contains("bacteria") | diag.contains("viral") | diag.contains("infect"), "Infectious Disease")
        .when(diag.contains("gastr") | diag.contains("intestin") | diag.contains("colon") | diag.contains("liver") | diag.contains("bowel") | diag.contains("digest"), "Gastroenterology")
        .when(diag.contains("newborn") | diag.contains("neonat") | diag.contains("prematurity") | diag.contains("infant"), "Neonatal")
        .when(diag.contains("pregnan") | diag.contains("delivery") | diag.contains("obstetric") | diag.contains("maternal"), "Obstetrics")
        .otherwise("Other")
    )

    # ---- Write raw stream to HDFS ----
    raw_query = (
        raw_stream.selectExpr("CAST(value AS STRING)")
        .writeStream.format("parquet")
        .option("path", RAW_PATH)
        .option("checkpointLocation", f"{CHECKPOINT_PATH}/raw")
        .outputMode("append")
        .start()
    )

    # ---- Write cleaned + enriched stream to HDFS ----
    processed_query = (
        cleaned.writeStream.format("parquet")
        .option("path", PROCESSED_PATH)
        .option("checkpointLocation", f"{CHECKPOINT_PATH}/processed")
        .outputMode("append")
        .start()
    )

    raw_query.awaitTermination()
    processed_query.awaitTermination()


if __name__ == "__main__":
    main()
