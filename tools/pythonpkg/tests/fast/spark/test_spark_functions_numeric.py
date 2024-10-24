import pytest

_ = pytest.importorskip("duckdb.experimental.spark")
from duckdb.experimental.spark.sql import functions as F
from duckdb.experimental.spark.sql.types import Row


class TestSparkFunctionsNumeric(object):
    def test_greatest(self, spark):
        data = [
            (1, 2),
            (4, 3),
        ]
        df = spark.createDataFrame(data, ["firstColumn", "secondColumn"])
        df = df.withColumn("greatest_value", F.greatest(F.col("firstColumn"), F.col("secondColumn")))
        res = df.select("greatest_value").collect()
        assert res == [
            Row(greatest_value=2),
            Row(greatest_value=4),
        ]

    def test_least(self, spark):
        data = [
            (1, 2),
            (4, 3),
        ]
        df = spark.createDataFrame(data, ["firstColumn", "secondColumn"])
        df = df.withColumn("least_value", F.least(F.col("firstColumn"), F.col("secondColumn")))
        res = df.select("least_value").collect()
        assert res == [
            Row(least_value=1),
            Row(least_value=3),
        ]

    def test_ceil(self, spark):
        data = [
            (1.1,),
            (2.9,),
        ]
        df = spark.createDataFrame(data, ["firstColumn"])
        df = df.withColumn("ceil_value", F.ceil(F.col("firstColumn")))
        res = df.select("ceil_value").collect()
        assert res == [
            Row(ceil_value=2),
            Row(ceil_value=3),
        ]

    def test_floor(self, spark):
        data = [
            (1.1,),
            (2.9,),
        ]
        df = spark.createDataFrame(data, ["firstColumn"])
        df = df.withColumn("floor_value", F.floor(F.col("firstColumn")))
        res = df.select("floor_value").collect()
        assert res == [
            Row(floor_value=1),
            Row(floor_value=2),
        ]

    def test_abs(self, spark):
        data = [
            (1.1,),
            (-2.9,),
        ]
        df = spark.createDataFrame(data, ["firstColumn"])
        df = df.withColumn("abs_value", F.abs(F.col("firstColumn")))
        res = df.select("abs_value").collect()
        assert res == [
            Row(abs_value=1.1),
            Row(abs_value=2.9),
        ]

    def test_sqrt(self, spark):
        data = [
            (4,),
            (9,),
        ]
        df = spark.createDataFrame(data, ["firstColumn"])
        df = df.withColumn("sqrt_value", F.sqrt(F.col("firstColumn")))
        res = df.select("sqrt_value").collect()
        assert res == [
            Row(sqrt_value=2.0),
            Row(sqrt_value=3.0),
        ]

    def test_cos(self, spark):
        data = [
            (0,),
            (3.14159,),
        ]
        df = spark.createDataFrame(data, ["firstColumn"])
        df = df.withColumn("cos_value", F.cos(F.col("firstColumn")))
        res = df.select("cos_value").collect()
        assert len(res) == 2
        assert res[0].cos_value == pytest.approx(1.0)
        assert res[1].cos_value == pytest.approx(-1.0)

    def test_acos(self, spark):
        data = [
            (1,),
            (-1,),
        ]
        df = spark.createDataFrame(data, ["firstColumn"])
        df = df.withColumn("acos_value", F.acos(F.col("firstColumn")))
        res = df.select("acos_value").collect()
        assert len(res) == 2
        assert res[0].acos_value == pytest.approx(0.0)
        assert res[1].acos_value == pytest.approx(3.141592653589793)
