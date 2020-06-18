select
 sum(l_extendedprice_decompressed * l_discount_decompressed) as revenue
from
 lineitem
where
 l_shipdate_decompressed >= cast('1994-01-01' as date)
 and l_shipdate_decompressed < cast('1995-01-01' as date)
 and l_discount_decompressed between 0.05 and 0.07
 and l_quantity_decompressed < 24;
