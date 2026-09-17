with open('quarkus/deployment/src/main/java/org/keycloak/quarkus/deployment/KeycloakProcessor.java', 'r') as f:
    content = f.read()

target = """        if (implicitOrmXml) {
            if (!descriptor.getManagedClassNames().isEmpty()) {
                mappingFiles.add("META-INF/orm.xml");
            } else {
                builder.mappingFile("no-file");
                return;
            }
        }"""

replacement = """        if (implicitOrmXml) {
            mappingFiles.add("META-INF/orm.xml");
        }"""

if target in content:
    with open('quarkus/deployment/src/main/java/org/keycloak/quarkus/deployment/KeycloakProcessor.java', 'w') as f:
        f.write(content.replace(target, replacement))
    print("Fixed!")
else:
    print("Not found!")
