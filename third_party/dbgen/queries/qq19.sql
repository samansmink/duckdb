select
 sum(l_extendedprice* (1 - l_discount)) as revenue
from
 lineitem,
 part
where
 (
 p_partkey = l_partkey
 and p_brand_dictkey = 11
 and p_container_dictkey in (27, 35, 21, 10)
 and l_quantity >= 1 and l_quantity <= 1 + 10
 and p_size between 1 and 5
 and l_shipmode_dictkey in (0, 7)
 and l_shipinstruct_dictkey = 2
 )
 or
 (
 p_partkey = l_partkey
 and p_brand_dictkey = 17
 and p_container_dictkey in (32, 3, 19, 2)
 and l_quantity >= 10 and l_quantity <= 10 + 10
 and p_size between 1 and 10
 and l_shipmode_dictkey in (0, 7)
 and l_shipinstruct_dictkey = 2
 )
 or
 (
 p_partkey = l_partkey
 and p_brand_dictkey = 23
 and p_container_dictkey in (1, 38, 36, 15)
 and l_quantity >= 20 and l_quantity <= 20 + 10
 and p_size between 1 and 15
 and l_shipmode_dictkey in (0, 7)
 and l_shipinstruct_dictkey = 2
 );
