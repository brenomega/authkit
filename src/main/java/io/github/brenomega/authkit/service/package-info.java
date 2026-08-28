/**
 * Coordinates authentication and account use cases across domain, persistence,
 * and infrastructure boundaries. Spring transactions in this package cover JPA
 * work only; Redis, broker, and external-provider effects are not distributed
 * participants unless a method explicitly states otherwise.
 */
package io.github.brenomega.authkit.service;
