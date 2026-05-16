-- Cross-domain foreign-key constraints — deferred to a final migration so each domain file can run independently (every referenced table exists by the time this file runs).
--
-- Wave H consolidation (tracker manchtools/power-manage-server#242):
-- replaces the 49 historical migrations with a small thematic set
-- containing the current schema. Existing deployments are broken on
-- purpose — fresh deploys run this set cleanly.
--
-- Generated from a pg_dump --schema-only of a testcontainer that
-- replayed every original migration, then split by domain. Order
-- between files is irrelevant for fresh setup; goose runs them in
-- numeric order.

-- +goose Up

--
-- Name: auth_states auth_states_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_states
    ADD CONSTRAINT auth_states_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.identity_providers_projection(id);

--
-- Name: device_labels device_labels_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_labels
    ADD CONSTRAINT device_labels_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices_projection(id) ON DELETE CASCADE;

--
-- Name: dynamic_user_group_evaluation_queue dynamic_user_group_evaluation_queue_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dynamic_user_group_evaluation_queue
    ADD CONSTRAINT dynamic_user_group_evaluation_queue_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.user_groups_projection(id);

--
-- Name: identity_links_projection identity_links_projection_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_links_projection
    ADD CONSTRAINT identity_links_projection_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.identity_providers_projection(id);

--
-- Name: identity_links_projection identity_links_projection_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_links_projection
    ADD CONSTRAINT identity_links_projection_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users_projection(id);

--
-- Name: scim_group_mapping_projection scim_group_mapping_projection_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_group_mapping_projection
    ADD CONSTRAINT scim_group_mapping_projection_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.identity_providers_projection(id);

--
-- Name: scim_group_mapping_projection scim_group_mapping_projection_user_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_group_mapping_projection
    ADD CONSTRAINT scim_group_mapping_projection_user_group_id_fkey FOREIGN KEY (user_group_id) REFERENCES public.user_groups_projection(id);

--
-- Name: security_alerts_projection security_alerts_projection_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_alerts_projection
    ADD CONSTRAINT security_alerts_projection_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(id);

--
-- Name: totp_projection totp_projection_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_projection
    ADD CONSTRAINT totp_projection_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users_projection(id);

--
-- Name: user_group_members_projection user_group_members_projection_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_members_projection
    ADD CONSTRAINT user_group_members_projection_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.user_groups_projection(id);

--
-- Name: user_group_members_projection user_group_members_projection_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_members_projection
    ADD CONSTRAINT user_group_members_projection_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users_projection(id);

--
-- Name: user_group_roles_projection user_group_roles_projection_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_roles_projection
    ADD CONSTRAINT user_group_roles_projection_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.user_groups_projection(id);

--
-- Name: user_group_roles_projection user_group_roles_projection_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_group_roles_projection
    ADD CONSTRAINT user_group_roles_projection_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles_projection(id);

--
-- Name: user_ssh_keys user_ssh_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_ssh_keys
    ADD CONSTRAINT user_ssh_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users_projection(id) ON DELETE CASCADE;

--
-- PostgreSQL database dump complete
--


-- +goose Down

-- Intentionally not reversible — see header.
SELECT 1;
