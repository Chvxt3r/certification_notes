Web Capstone Notes

IP: 10.9.76.12

# Findings
## IDOR in main application
  * Application allows direct access to different changes by chaing the 'coffee=1' variable
    http://10.19.76.12/capstone/coffee.php?coffee=3

## XSS in main application (Login Required)
  * "Add rating" functionality allows xss in the comment field.

## Backend DB is vulerable to injection on the coffee variable

```bash
Table: users
[9 entries]
+---------+--------+--------------------------------------------------------------+----------+
| user_id | type   | password                                                     | username |
+---------+--------+--------------------------------------------------------------+----------+
| 1       | admin  | $2y$10$F9bvqz5eoawIS6g0FH.wGOUkNdBYLFBaCSzXvo2HTegQdNg/HlMJy | jeremy   |
| 2       | admin  | $2y$10$meh2WXtPZgzZPZrjAmHi2ObKk6uXd2yZio7EB8t.MVuV1KwhWv6yS | jessamy  |
| 3       | admin  | $2y$10$cCXaMFLC.ymTSqu1whYWbuU38RBN900NutjYBvCClqh.UHHg/XfFy | raj      |
| 4       | user   | $2y$10$ojC8YCMKX2r/Suqco/h.TOFTIaw5k3Io5FVSCeWjCCqL8GWwmAczC | bob      |
| 5       | user   | $2y$10$EPM4Unjn4wnn4SjoEPJu7em6OLISImA50QS3T1jCLyh48d7Pv6KBi | maria    |
| 6       | user   | $2y$10$qAXjb233b7CMHc69CU.8ueluFWZDt9f08.XYJjsJ.EfC/O5JGSOqW | amir     |
| 7       | user   | $2y$10$37gojoTFmj86E6NbENGg9e2Xu2z6OKKSgnjYxDkXJn/8dvSk2tKfG | xinyi    |
| 8       | user   | $2y$10$5sVvPfZOjzRTSeXJtQBGc.CfsDEwvITNkIg2IF9jSBhZZ1Rq.IK3. | kofi     |
| 9       | user   | $2y$10$w.S/gafFLeH/5hfWnTadBOzL5hPmU/./OB/.XAqP9i.Uz4Wp5I7Pm | chvxt3r  |
+---------+--------+--------------------------------------------------------------+----------+
```

## Passwords are easily cracked
$2y$10$F9bvqz5eoawIS6g0FH.wGOUkNdBYLFBaCSzXvo2HTegQdNg/HlMJy:captain1

test
