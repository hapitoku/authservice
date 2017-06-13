FROM java:8-jre 
MAINTAINER wanghua

ADD frm-authservice-1.0.1-SNAPSHOT.jar /usr/local

EXPOSE 7080
CMD ["java","-Xmx1g","-Duser.timezone=GMT+8","-jar","-Dspring.cloud.bootstrap.location=/usr/conf/bootstrap.properties","/usr/local/frm-authservice-1.0.1-SNAPSHOT.jar"]