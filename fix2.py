with open('quarkus/deployment/src/main/java/org/keycloak/quarkus/deployment/KeycloakProcessor.java', 'r') as f:
    content = f.read()

target = """        try (QuarkusMappingFileParser parser = QuarkusMappingFileParser.create()) {
            for (String mappingFile : mappingFiles) {
                logger.debugf("Parsing mapping file '%s' for PU '%s' with root URL '%s'",
                        mappingFile, descriptor.getName(), descriptor.getPersistenceUnitRootUrl());
                Optional<RecordableXmlMapping> mappingOptional = parser.parse(
                        descriptor.getName(), descriptor.getPersistenceUnitRootUrl(), mappingFile);
                logger.debugf("Parsed mapping file result present: %s", mappingOptional.isPresent());"""

replacement = """        try (QuarkusMappingFileParser parser = QuarkusMappingFileParser.create()) {
            for (String mappingFile : mappingFiles) {
                logger.infof("TEST_LOG_PREFIX: PU=%s URL=%s File=%s", descriptor.getName(), descriptor.getPersistenceUnitRootUrl(), mappingFile);
                Optional<RecordableXmlMapping> mappingOptional = parser.parse(
                        descriptor.getName(), descriptor.getPersistenceUnitRootUrl(), mappingFile);
                logger.infof("TEST_LOG_PREFIX: PU=%s Present=%s", descriptor.getName(), mappingOptional.isPresent());"""

if target in content:
    with open('quarkus/deployment/src/main/java/org/keycloak/quarkus/deployment/KeycloakProcessor.java', 'w') as f:
        f.write(content.replace(target, replacement))
    print("Fixed!")
else:
    print("Not found!")
