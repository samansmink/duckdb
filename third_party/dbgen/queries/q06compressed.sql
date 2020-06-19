select
 sum((CAST(l_extendedprice_compressed AS DOUBLE)/10000) * (CAST(l_discount_compressed AS DOUBLE)/100)) as revenue
from
 lineitem
where
 l_shipdate_compressed >= 1994
 and l_shipdate_compressed < 1995
 and l_discount_compressed between 5 and 7
 and l_quantity_compressed < 24;