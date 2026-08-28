/**
 * Enforces edge-origin trust, client-address resolution, request sizing, and
 * layered abuse limits before controller use cases execute. Trust in forwarded
 * headers depends on deployment perimeter configuration and is not established by
 * the header value itself.
 */
package io.github.brenomega.authkit.infrastructure.network;
