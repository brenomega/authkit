/**
 * Adapts asynchronous email publication and consumption to RabbitMQ. Broker
 * acceptance and consumer execution are separate outcomes, and delivery may be
 * repeated.
 */
package io.github.brenomega.authkit.infrastructure.queue;
