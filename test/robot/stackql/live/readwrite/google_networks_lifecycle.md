



```sql

--
insert into google.compute.networks(data__name, data__autoCreateSubnetworks, project) 
select 'robot-vpc-01', false, 'stackql-robot';
The operation was despatched successfully

--
select id, name, description, subnetworks from google.compute.networks where name = 'robot-vpc-01' and project = 'stackql-robot';
|--------------------|--------------|-------------|-------------|
|         id         |     name     | description | subnetworks |
|--------------------|--------------|-------------|-------------|
| 987158103920671616 | robot-vpc-01 | null        | null        |
|--------------------|--------------|-------------|-------------|

--
insert into google.compute.subnetworks(data__name, data__ipCidrRange, data__description, data__network, project, region) 
select 
'robot-subnet-01', 
'10.0.0.0/8',
'An immutable ROBOT subnet description.', 
'projects/stackql-robot/global/networks/robot-vpc-01',
'stackql-robot',
'australia-southeast1'
;
The operation was despatched successfully

---
select id, name, description, subnetworks from google.compute.networks where name = 'robot-vpc-01' and project = 'stackql-robot';
|--------------------|--------------|-------------|---------------------------------------------------------------------------------------------------------------------------|
|         id         |     name     | description |                                                        subnetworks                                                        |
|--------------------|--------------|-------------|---------------------------------------------------------------------------------------------------------------------------|
| 987158103920671616 | robot-vpc-01 | null        | ["https://www.googleapis.com/compute/v1/projects/stackql-robot/regions/australia-southeast1/subnetworks/robot-subnet-01"] |
|--------------------|--------------|-------------|---------------------------------------------------------------------------------------------------------------------------|

--
select name, id, secondaryIpRanges, fingerprint from google.compute.subnetworks where name = 'robot-subnet-01' and region = 'australia-southeast1' and project = 'stackql-robot' ;
|-----------------|---------------------|-------------------|--------------|
|      name       |         id          | secondaryIpRanges | fingerprint  |
|-----------------|---------------------|-------------------|--------------|
| robot-subnet-01 | 7691273977604797678 | null              | UNiA_jWveJI= |
|-----------------|---------------------|-------------------|--------------|


---
update google.compute.subnetworks
SET
data__secondaryIpRanges = '[
   {
     "ipCidrRange": "192.168.0.0/24",
     "rangeName": "robot-range-01"
   }
 ]', 
data__fingerprint = 'UNiA_jWveJI='
WHERE
project = 'stackql-robot'
and
region = 'australia-southeast1'
and
subnetwork = 'robot-subnet-01'
;
The operation was despatched successfully

--
select name, id, secondaryIpRanges, fingerprint from google.compute.subnetworks where name = 'robot-subnet-01' and region = 'australia-southeast1' and project = 'stackql-robot' ;
|-----------------|---------------------|-----------------------------------------------------------------|--------------|
|      name       |         id          |                        secondaryIpRanges                        | fingerprint  |
|-----------------|---------------------|-----------------------------------------------------------------|--------------|
| robot-subnet-01 | 7691273977604797678 | [{"ipCidrRange":"192.168.0.0/24","rangeName":"robot-range-01"}] | vmdP1iA6Cfc= |
|-----------------|---------------------|-----------------------------------------------------------------|--------------|


--
delete from 
google.compute.subnetworks
WHERE
project = 'stackql-robot'
and
region = 'australia-southeast1'
and
subnetwork = 'robot-subnet-01'
;
<nil displayed response>

--
select name, id, secondaryIpRanges, fingerprint from google.compute.subnetworks where name = 'robot-subnet-01' and region = 'australia-southeast1' and project = 'stackql-robot' ;
|------|----|-------------------|-------------|
| name | id | secondaryIpRanges | fingerprint |
|------|----|-------------------|-------------|


--
delete from 
google.compute.networks
WHERE
project = 'stackql-robot'
and
network = 'robot-vpc-01'
;
<nil displayed response>


--
select id, name, description, subnetworks from google.compute.networks where name = 'robot-vpc-01' and project = 'stackql-robot';
|----|------|-------------|-------------|
| id | name | description | subnetworks |
|----|------|-------------|-------------|

```

## Notes

- Even compute api is not on by default in a new google project.

