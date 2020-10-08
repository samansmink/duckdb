select
 l_shipmode_dictkey,
 sum(case
 when o_orderpriority_dictkey = 0
 or o_orderpriority_dictkey = 3
 then 1
 else 0
 end) as high_line_count,
 sum(case
 when o_orderpriority_dictkey <> 0
 and o_orderpriority_dictkey <> 3
 then 1
 else 0
 end) as low_line_count
from
 orders,
 lineitem
where
 o_orderkey = l_orderkey
 and l_shipmode_dictkey in (4, 5)
 and l_commitdate < l_receiptdate
 and l_shipdate < l_commitdate
 and l_receiptdate >= cast('1994-01-01' as date)
 and l_receiptdate < cast('1995-01-01' as date)
group by
 l_shipmode_dictkey
order by
 l_shipmode_dictkey;
