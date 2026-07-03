package org.springframework.web.bind.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

// Minimal stub of Spring's @RequestParam so this fixture compiles with the JDK
// alone (no Spring on the classpath). Only the annotation's presence — its
// runtime-visible type name org/springframework/web/bind/annotation/RequestParam
// — matters to the analyzer, which synthesizes a taint source for parameters
// carrying it (see converters/java/lower.go and the java:*RequestParam source
// glob). Real Spring apps are analyzed from compiled bytecode; see
// test/java/spring_boot for an end-to-end build.
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface RequestParam {}
