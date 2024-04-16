
select svreq.reqno,request_date,dn,expire_date from svreq,svcrt where svreq.reqno=svcrt.reqno and svreq.status=2 and svcrt.status=0 limit 20;
