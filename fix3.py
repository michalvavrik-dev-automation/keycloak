with open('quarkus/deployment/src/main/java/org/keycloak/quarkus/deployment/KeycloakProcessor.java', 'r') as f:
    content = f.read()

target = """        try (QuarkusMappingFileParser parser = QuarkusMappingFileParser.create()) {
            for (String mappingFile : mappingFiles) {
                logger.infof("TEST_LOG_PREFIX: PU=%s URL=%s File=%s", descriptor.getName(), descriptor.getPersistenceUnitRootUrl(), mappingFile);
                Optional<RecordableXmlMapping> mappingOptional = parser.parse(
                        descriptor.getName(), descriptor.getPersistenceUnitRootUrl(), mappingFile);
                logger.infof("TEST_LOG_PREFIX: PU=%s Present=%s", descriptor.getName(), mappingOptional.isPresent());"""

replacement = """        try (QuarkusMappingFileParser parser = QuarkusMappingFileParser.create()) {
            for (String mappingFile : mappingFiles) {
                System.out.println("TEST_LOG_PREFIX: PU=" + descriptor.getName() + " URL=" + descriptor.getPersistenceUnitRootUrl() + " File=" + mappingFile);
                Optional<RecordableXmlMapping> mappingOptional = parser.parse(
                        descriptor.getName(), descriptor.getPersistenceUnitRootUrl(), mappingFile);
                System.out.println("TEST_LOG_PREFIX: PU=" + descriptor.getName() + " Present=" + mappingOptional.isPresent());"""

if target in content:
    with open('quarkus/deployment/src/main/java/org/keycloak/quarkus/deployment/KeycloakProcessor.java', 'w') as f:
        f.write(content.replace(target, replacement))
    print("Fixed!")
else:
    print("Not found!")
