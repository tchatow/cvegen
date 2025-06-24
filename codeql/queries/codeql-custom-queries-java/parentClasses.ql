import java

from ClassOrInterface ci, ClassOrInterface pi
where pi.hasSubtype(ci) and
pi.getQualifiedName() != "java.lang.Object" and
(ci.getQualifiedName().matches("org.apache.arrow.%") or
 ci.getQualifiedName().matches("net.lingala.zip4j.%") or
 ci.getQualifiedName().matches("org.apache.tomcat.%") or
 ci.getQualifiedName().matches("org.apache.juli.%") or
 ci.getQualifiedName().matches("org.apache.catalina.%") or
 ci.getQualifiedName().matches("org.apache.jasper.%") or
 ci.getQualifiedName().matches("org.apache.coyote.%") or
 ci.getQualifiedName().matches("org.apache.tika.%")
)
select ci.getQualifiedName() as child,
    pi.getQualifiedName() as parent