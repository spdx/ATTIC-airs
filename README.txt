How to execute AIRS

1. Below are necessary for running AIRS
 - Java runtime (above v1.6)
 - Protex SDK jars (above v6.2)
  : blackduck-cxf-utilities-1.1.jar, protex-sdk-client.jar, protex-sdk-utilities.jar 
   (future version of AIRS will support more various tools)

2. Execute com.sec.ose.airs.CLIMain or jar archive
 - Options
 [export]
  export -h [Protex Server Address] -u [user Id] -p [user password] --proxy-host [proxy address] --proxy-port [proxy port] --project-id [project ID] -o [exported file name (*.rdf)]
 [auto identify]
  ai -h [Protex Server address] -u [User ID] -p [User Password] --proxy-host [proxy Address] --proxy-port [proxy port] --project-id [project id] --spdx-files [list spdx files seperated by blank(" ")]  