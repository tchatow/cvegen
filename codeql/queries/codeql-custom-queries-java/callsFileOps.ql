import java

predicate isJazzerFileMethod(Callable c) {
  exists(string n | n = c.getQualifiedName() and (
    n = "java.nio.file.Files.createDirectory" or
    n = "java.nio.file.Files.createDirectories" or
    n = "java.nio.file.Files.createFile" or
    n = "java.nio.file.Files.createTempDirectory" or
    n = "java.nio.file.Files.createTempFile" or
    n = "java.nio.file.Files.delete" or
    n = "java.nio.file.Files.deleteIfExists" or
    n = "java.nio.file.Files.lines" or
    n = "java.nio.file.Files.newByteChannel" or
    n = "java.nio.file.Files.newBufferedReader" or
    n = "java.nio.file.Files.newBufferedWriter" or
    n = "java.nio.file.Files.readString" or
    n = "java.nio.file.Files.readAllBytes" or
    n = "java.nio.file.Files.readAllLines" or
    n = "java.nio.file.Files.readSymbolicLink" or
    n = "java.nio.file.Files.write" or
    n = "java.nio.file.Files.writeString" or
    n = "java.nio.file.Files.newInputStream" or
    n = "java.nio.file.Files.newOutputStream" or
    n = "java.nio.file.probeContentType.open" or
    n = "java.nio.channels.FileChannel.open" or
    n = "java.nio.file.Files.copy" or
    n = "java.nio.file.Files.mismatch" or
    n = "java.nio.file.Files.move" or
    n = "java.io.FileReader.FileReader" or
    n = "java.io.FileWriter.FileWriter" or
    n = "java.io.FileInputStream.FileInputStream" or
    n = "java.io.FileOutputStream.FileOutputStream" or
    n = "java.util.Scanner.Scanner" or
    n = "javax.naming.directory.DirContext.search" or
    n = "java.nio.channels.SocketChannel.connect" or
    n = "java.sql.Statement.execute" or
    n = "java.sql.Statement.executeBatch" or
    n = "java.sql.Statement.executeLargeBatch" or
    n = "java.sql.Statement.executeLargeUpdate" or
    n = "java.sql.Statement.executeQuery" or
    n = "java.sql.Statement.executeUpdate" or
    n = "javax.persistence.EntityManager.createNativeQuery" or
    n = "java.lang.ProcessImpl.start" or
    n = "java.lang.ProcessBuilder.ProcessBuilder" or
    n = "java.lang.ProcessBuilder.command" or
    n = "java.io.ObjectInputStream.ObjectInputStream" or
    n = "javax.xml.xpath.XPath.compile" or
    n = "javax.xml.xpath.XPath.evaluate" or
    n = "javax.xml.xpath.XPath.evaluateExpression"
  ))
}

from Callable caller, Callable c where
  caller.polyCalls(c) and
  isJazzerFileMethod(c)
select c.getQualifiedName() as fqn, caller.getQualifiedName() as callerFqn