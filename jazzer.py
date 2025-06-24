ALL_JAZZER_SANITIZERS = {
  'directory_traversal': {
    'methods': [
      "java.nio.file.Files.createDirectory",
      "java.nio.file.Files.createDirectories",
      "java.nio.file.Files.createFile",
      "java.nio.file.Files.createTempDirectory",
      "java.nio.file.Files.createTempFile",
      "java.nio.file.Files.delete",
      "java.nio.file.Files.deleteIfExists",
      "java.nio.file.Files.lines",
      "java.nio.file.Files.newByteChannel",
      "java.nio.file.Files.newBufferedReader",
      "java.nio.file.Files.newBufferedWriter",
      "java.nio.file.Files.readString",
      "java.nio.file.Files.readAllBytes",
      "java.nio.file.Files.readAllLines",
      "java.nio.file.Files.readSymbolicLink",
      "java.nio.file.Files.write",
      "java.nio.file.Files.writeString",
      "java.nio.file.Files.newInputStream",
      "java.nio.file.Files.newOutputStream",
      "java.nio.file.probeContentType.open",
      "java.nio.channels.FileChannel.open",
      "java.nio.file.Files.copy",
      "java.nio.file.Files.mismatch",
      "java.nio.file.Files.move",
      "java.io.FileReader.<init>",
      "java.io.FileWriter.<init>",
      "java.io.FileInputStream.<init>",
      "java.io.FileOutputStream.<init>",
      "java.util.Scanner.<init>"
    ],
    'prompt': 'You will be injecting a directory traversal vulnerability. This bug allows '
              'user data to flow to a File operation, permitting arbitrary access to files '
              'outside of predefined locations. The attacker must be able to access an arbitrary path, '
              'merely controlling the file name within a safe directory is not sufficient. '
  },
  'ldap_injection': {
    'methods': [
      "javax.naming.directory.DirContext.search"
      #"javax.naming.directory.InitialDirContext.search"
    ],
    'prompt': 'You will be injecting an LDAP vulernability. '
              'LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. '
  },
  'ssrf': {
    'methods': [
      "java.nio.channels.SocketChannel.connect",
      #"sun.nio.ch.SocketAdaptor.connect",
      #"jdk.internal.net.http.PlainHttpConnection.connect"
    ],
    'prompt': ""
  },
  'sql_injection': {
    'methods': [
      "java.sql.Statement.execute",
      "java.sql.Statement.executeBatch",
      "java.sql.Statement.executeLargeBatch",
      "java.sql.Statement.executeLargeUpdate",
      "java.sql.Statement.executeQuery",
      "java.sql.Statement.executeUpdate",
      "javax.persistence.EntityManager.createNativeQuery"
    ],
    'prompt': ""
  },
  'os_command_injection': {
    'methods': [
      "java.lang.ProcessImpl.start",
      "java.lang.ProcessBuilder.<init>",
      "java.lang.ProcessBuilder.command"
    ],
    'prompt': 'You will be injecting an os command injection vulnerability. This bug allows '
              'user data to flow to a command invocation, permitting execution of arbitrary programs. '
              'The attacker must be able to execute arbitrary programs, either directly or through an '
              'unsafe shell. Merely controlling a particular argument to the process is not sufficient. '
  },
  'deserialization': {
    'methods': [
      "java.io.ObjectInputStream.<init>"
      #"java.io.ObjectInputStream.readObject",
    ],
    'prompt': "You will be injecting a deserialization vulnerability. This permits an attacker "
              "to load arbitrary classes. For this attack to be possible, the attacker must both "
              "control the input to the constructor of java.io.ObjectInputStream, and at least one "
              "of its readObject, readObjectOverride, or readUnshared methods must be invoked. "
              "Methods such as readUTF are not vulnerable, since they do not deserialize arbitrary objects."
  },
  'xpath_injection': {
    'methods': [
      "javax.xml.xpath.XPath.compile",
      "javax.xml.xpath.XPath.evaluate",
      "javax.xml.xpath.XPath.evaluateExpression"
    ]
  }
}