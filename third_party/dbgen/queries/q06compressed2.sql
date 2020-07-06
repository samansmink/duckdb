select
 sum(CAST(l_extendedprice_compressed AS BIGINT) * CAST(l_discount_compressed AS BIGINT)) as revenue
from
 lineitem
where
 l_shipdate_compressed >= 1994
 and l_shipdate_compressed < 1995
 and l_discount_compressed between 5 and 7
 and l_quantity_compressed < 24;