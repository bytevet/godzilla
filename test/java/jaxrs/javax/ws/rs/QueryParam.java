package javax.ws.rs;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

// Minimal stub of JAX-RS @QueryParam so this fixture compiles with the JDK alone
// (no JAX-RS on the classpath). Only the annotation's runtime-visible type name
// javax/ws/rs/QueryParam matters to the analyzer, which synthesizes a taint
// source for parameters carrying it (see the java:*ws/rs/QueryParam source glob).
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface QueryParam {
    String value();
}
