#!/usr/bin/env python3
"""Unit tests for tenant_scope.py.

Style mirrors the offboarding suite: stdlib unittest, no fixtures on disk
beyond temp dirs, weight on the findings engine (fixture CSVs -> expected
findings), plus preflight parsing, exit-60/empty-CSV handling and manifest
resume. No GAM calls are made anywhere in here.
"""

import argparse
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

import tenant_scope as ts


def make_args(**overrides):
    base = dict(admin="admin@example.com", output_dir=None, run_dir=None,
                list=False, only=None, skip=None, skip_tier=None, full=False,
                no_dns=False, include_suspended=False,
                skip_never_logged_in=False, no_open=True,
                grant_temp_access=False, render_only=False, dry_run=False,
                yes=True, compare_with=None)
    base.update(overrides)
    return argparse.Namespace(**base)


def setUpModule():
    """Silence the script's console output for the whole suite.

    With no logger configured, _emit falls back to print(), so running the
    tests emitted a STAGE 2 CHECK block full of CRITICAL findings from
    fixture data. A tester read that as a report on their own tenant
    (Kim Nilsson, 2026-08-17).
    """
    global _emit_original
    _emit_original = ts._emit
    ts._emit = lambda level, text: None


def tearDownModule():
    ts._emit = _emit_original


class CtxTestCase(unittest.TestCase):
    """Base: a temp run dir with helpers to drop fixture CSVs in."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self._tmp.name)
        self.ctx = ts.RunContext(self.run_dir, make_args())
        self.ctx.internal_domains = ["example.com", "alias.example.com"]

    def tearDown(self):
        self._tmp.cleanup()

    def write_csv(self, key, text, status="ok"):
        (self.run_dir / f"{key}.csv").write_text(text.strip() + "\n",
                                                 encoding="utf-8")
        rows = max(0, len(text.strip().splitlines()) - 1)
        self.ctx.set_module(key, status if rows else "empty", rows)

    def finding_ids(self, findings):
        return [f.fid for f in findings]


USERS_HEADER = ("primaryEmail,suspended,archived,lastLoginTime,"
                "isEnrolledIn2Sv,isEnforcedIn2Sv,recoveryEmail,isAdmin,"
                "isDelegatedAdmin,LicensesDisplay")


class TestSuperAdminChecks(CtxTestCase):
    def test_single_super_admin_is_critical(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business
user@example.com,False,False,2026-08-01T10:00:00Z,True,False,,False,False,Business""")
        ids = self.finding_ids(ts.check_super_admin_count(self.ctx))
        self.assertIn("few-super-admins", ids)

    def test_two_super_admins_is_clean(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business
boss2@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business""")
        self.assertEqual([], ts.check_super_admin_count(self.ctx))

    def test_suspended_admin_does_not_count(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business
old@example.com,True,False,2026-08-01T10:00:00Z,True,True,,True,False,Business""")
        ids = self.finding_ids(ts.check_super_admin_count(self.ctx))
        self.assertIn("few-super-admins", ids)

    def test_admin_without_2sv(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,False,False,,True,False,Business""")
        findings = ts.check_admin_2sv(self.ctx)
        self.assertEqual(["admin-no-2sv"], self.finding_ids(findings))
        self.assertEqual("CRITICAL", findings[0].severity)

    def test_admin_personal_recovery_email(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,boss@gmail.com,True,False,Business""")
        ids = self.finding_ids(ts.check_admin_recovery(self.ctx))
        self.assertIn("admin-personal-recovery", ids)

    def test_admin_internal_recovery_email_clean(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,other@example.com,True,False,Business""")
        self.assertEqual([], ts.check_admin_recovery(self.ctx))

    def test_admin_with_asps(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business""")
        self.write_csv("asps", """User,codeId,name,creationTime
boss@example.com,1,Old mail app,2025-01-01T00:00:00Z""")
        ids = self.finding_ids(ts.check_admin_asps(self.ctx))
        self.assertIn("admin-asps", ids)

    def test_non_admin_asps_clean(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business""")
        self.write_csv("asps", """User,codeId,name,creationTime
user@example.com,1,Old mail app,2025-01-01T00:00:00Z""")
        self.assertEqual([], ts.check_admin_asps(self.ctx))

    def test_zero_count_rows_are_not_asps(self):
        """GAM emits one `user,0` row per user when nobody holds an ASP;
        counting rows flagged every account in a clean tenant (2026-08-17)."""
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business""")
        self.write_csv("asps", """User,asps
boss@example.com,0
user@example.com,0""")
        self.assertEqual([], ts.check_admin_asps(self.ctx))
        self.assertEqual([], ts._asp_rows(self.ctx))

    def test_admin_backup_codes_zero_flagged_unread_skipped(self):
        # Dev shape: counts of 0 and 10. other@ is a super admin with no
        # backupcodes row, so it was not read and must not count as zero.
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business
boss2@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business
other@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business
user@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Business""")
        self.write_csv("backupcodes", """User,verificationCodesCount
boss@example.com,0
boss2@example.com,10
user@example.com,0""")
        findings = ts.check_admin_backup_codes(self.ctx)
        self.assertEqual(["admin-no-backup-codes"], self.finding_ids(findings))
        self.assertEqual(["boss@example.com"],
                         [e["Super admin"] for e in findings[0].evidence])

    def test_licensed_super_admin_info_cloud_identity_ignored(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business Standard
break@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Cloud Identity Free""")
        findings = ts.check_licensed_super_admins(self.ctx)
        self.assertEqual(["licensed-super-admins"], self.finding_ids(findings))
        self.assertEqual(["boss@example.com"],
                         [e["Super admin"] for e in findings[0].evidence])

    def test_nonzero_count_row_counts_as_asp(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business""")
        self.write_csv("asps", """User,asps
boss@example.com,2""")
        ids = self.finding_ids(ts.check_admin_asps(self.ctx))
        self.assertIn("admin-asps", ids)


class TestForwardingChecks(CtxTestCase):
    def test_external_forward_found(self):
        self.write_csv("forwards", """User,forwardEnabled,forwardTo,disposition
user@example.com,True,rival@gmail.com,archive""")
        findings = ts.check_external_forwarding(self.ctx)
        self.assertEqual(["external-forwarding"], self.finding_ids(findings))
        self.assertEqual("CRITICAL", findings[0].severity)

    def test_internal_forward_clean(self):
        self.write_csv("forwards", """User,forwardEnabled,forwardTo,disposition
user@example.com,True,team@alias.example.com,archive""")
        self.assertEqual([], ts.check_external_forwarding(self.ctx))

    def test_disabled_forward_clean(self):
        self.write_csv("forwards", """User,forwardEnabled,forwardTo,disposition
user@example.com,False,rival@gmail.com,archive""")
        self.assertEqual([], ts.check_external_forwarding(self.ctx))

    def test_filter_forwarding_external(self):
        self.write_csv("filters", """User,id,from,forward
user@example.com,f1,boss@example.com,leak@evil.example.net""")
        ids = self.finding_ids(ts.check_filter_forwarding(self.ctx))
        self.assertIn("filter-external-forwarding", ids)

    def test_filter_forwarding_strips_gam_action_verb(self):
        # Live GAM output: the cell is "forward <address>", not the address.
        self.write_csv("filters", """User,id,from,forward
user@example.com,f1,vendor@example.com,forward leak@evil.example.net""")
        findings = ts.check_filter_forwarding(self.ctx)
        self.assertIn("filter-external-forwarding", self.finding_ids(findings))
        self.assertEqual("leak@evil.example.net",
                         findings[0].evidence[0]["Filter forwards to"])

    def test_filter_forwarding_internal_clean(self):
        self.write_csv("filters", """User,id,from,forward
user@example.com,f1,boss@example.com,team@example.com""")
        self.assertEqual([], ts.check_filter_forwarding(self.ctx))

    BEC_HEADER = "User,id,from,subject,query,label,trash,archive,markread"

    def bec(self, line):
        self.write_csv("filters", f"{self.BEC_HEADER}\n{line}")
        return ts.check_filter_bec(self.ctx)

    def test_bec_payment_word_plus_trash_fires(self):
        # GAM7 prefixes each value with its column name.
        found = self.bec("u@example.com,f1,,subject Invoice 2231,,,trash,,")
        self.assertEqual(["filter-bec-patterns"], self.finding_ids(found))
        self.assertEqual("hides mail about 'invoice'",
                         found[0].evidence[0]["Why"])

    def test_bec_payment_word_with_only_a_label_is_clean(self):
        self.assertEqual([], self.bec(
            "u@example.com,f1,,subject invoice,,label Accounts,,,"))

    def test_bec_word_inside_another_word_is_clean(self):
        # "eft" in "left", "ceo" in "ceorganic": whole words only.
        self.assertEqual([], self.bec(
            "u@example.com,f1,,subject who left the office,,,trash,,"))

    def test_bec_single_external_sender_marked_read_fires(self):
        found = self.bec(
            "u@example.com,f1,from ceo@lookalike.example.net,,,,,,markread")
        self.assertEqual("hides mail from ceo@lookalike.example.net",
                         found[0].evidence[0]["Why"])

    def test_bec_newsletter_archived_is_clean(self):
        self.assertEqual([], self.bec(
            "u@example.com,f1,from news@vendor.example.net,,,,,archive,"))
        self.assertEqual([], self.bec(
            "u@example.com,f1,from boss@example.com,,,,trash,,"))

    def test_bec_blending_label_fires(self):
        found = self.bec(
            "u@example.com,f1,from x@vendor.example.net,,,label RSS Feeds,,archive,")
        self.assertIn("label 'RSS Feeds'", found[0].evidence[0]["Why"])

    def test_bec_partial_sweep_is_stated(self):
        self.write_csv("filters", f"""{self.BEC_HEADER}
u@example.com,f1,,query wire transfer,,,trash,,""", status="partial")
        found = ts.check_filter_bec(self.ctx)
        self.assertIn("only be read for some users", found[0].meaning)


class TestDriveChecks(CtxTestCase):
    FILELIST_HEADER = ("Owner,id,name,mimeType,owners.0.emailAddress,"
                       "permission.id,permission.type,permission.role,"
                       "permission.emailAddress,permission.domain,"
                       "permission.allowFileDiscovery")

    def test_public_on_web_is_critical(self):
        self.write_csv("mydrive_external", f"""{self.FILELIST_HEADER}
u@example.com,f1,Plans.docx,application/vnd.google-apps.document,u@example.com,anyoneWithLink,anyone,reader,,,True""")
        findings = ts.check_public_files(self.ctx)
        ids = self.finding_ids(findings)
        self.assertIn("public-files-mydrive_external", ids)

    def test_link_only_below_threshold_clean(self):
        rows = "\n".join(
            f"u@example.com,f{i},Doc{i},doc,u@example.com,anyoneWithLink,"
            f"anyone,reader,,,False" for i in range(3))
        self.write_csv("mydrive_external", f"{self.FILELIST_HEADER}\n{rows}")
        self.assertEqual([], ts.check_public_files(self.ctx))

    def test_link_only_at_scale_is_high(self):
        rows = "\n".join(
            f"u@example.com,f{i},Doc{i},doc,u@example.com,anyoneWithLink,"
            f"anyone,reader,,,False" for i in range(ts.ANYONE_LINK_SCALE))
        self.write_csv("mydrive_external", f"{self.FILELIST_HEADER}\n{rows}")
        findings = ts.check_public_files(self.ctx)
        self.assertEqual(["anyone-link-mydrive_external"],
                         self.finding_ids(findings))
        self.assertEqual("HIGH", findings[0].severity)

    def test_orphaned_shared_drive(self):
        self.write_csv("shareddriveorganizers", """id,name,organizers
sd1,Leaver Sole Manager SD,
sd2,Healthy Drive,alive@example.com""")
        findings = ts.check_orphaned_shared_drives(self.ctx)
        self.assertEqual(["orphaned-shared-drives"],
                         self.finding_ids(findings))
        self.assertEqual(1, findings[0].count)

    def test_shared_drive_external_member(self):
        self.write_csv("shareddriveacls", """id,name,permission.id,permission.type,permission.emailAddress,permission.role,permission.deleted
sd1,Client Drive,p1,user,partner@other.example.net,writer,False
sd1,Client Drive,p2,user,staff@example.com,organizer,False""")
        findings = ts.check_shared_drive_external(self.ctx)
        ids = self.finding_ids(findings)
        self.assertIn("sd-external-members", ids)
        self.assertEqual(1, findings[0].count)
        self.assertEqual("not scanned", findings[0].evidence[0]["Files in drive"])

    def test_shared_drive_members_with_file_count_and_outside_domain(self):
        self.ctx.manifest["meta"]["shared_drive_file_counts"] = {"sd1": 3000}
        self.write_csv("shareddriveacls", """id,name,permission.id,permission.type,permission.emailAddress,permission.domain,permission.role,permission.deleted
sd1,Client Drive,p1,user,partner@other.example.net,other.example.net,reader,False
sd1,Client Drive,p2,domain,,partner.example.org,reader,False
sd1,Client Drive,p3,domain,,example.com,reader,False""")
        found = ts.check_shared_drive_external(self.ctx)[0]
        self.assertEqual(
            [("partner@other.example.net", "3000"),
             ("everyone at partner.example.org", "3000")],
            [(r["External member"], r["Files in drive"])
             for r in found.evidence])

    def test_deleted_user_acl_not_external(self):
        # Deleted users remain as ACL rows with permission.deleted=True and
        # an EMPTY email; they must not be reported as external members.
        self.write_csv("shareddriveacls", """id,name,permission.id,permission.type,permission.emailAddress,permission.role,permission.deleted
sd1,Old Drive,p1,user,,organizer,True""")
        self.assertEqual([], ts.check_shared_drive_external(self.ctx))

    def test_open_shared_drive_settings(self):
        self.write_csv("shareddrives", """id,name,restrictions.domainUsersOnly,restrictions.driveMembersOnly
sd1,Open Drive,False,False
sd2,Locked Drive,True,True""")
        findings = ts.check_shared_drive_external(self.ctx)
        self.assertEqual(["sd-open-settings"], self.finding_ids(findings))
        self.assertEqual(1, findings[0].count)


class TestExternalFileShareChecks(CtxTestCase):
    MYDRIVE_HEADER = ("Owner,id,name,mimeType,owners,owners.0.emailAddress,"
                      "permission.type,permission.emailAddress,"
                      "permission.domain,permission.role,"
                      "permission.allowFileDiscovery")

    def test_named_and_domain_external_shares_found(self):
        self.write_csv("mydrive_external", self.MYDRIVE_HEADER + "\n"
                       "u@example.com,f1,ext.doc,doc,1,u@example.com,"
                       "user,out@other.com,other.com,reader,\n"
                       "u@example.com,f2,dom.doc,doc,1,u@example.com,"
                       "domain,,other.com,reader,\n"
                       "u@example.com,f4,aud.doc,doc,1,u@example.com,"
                       "domain,,c03abc.audience.googledomains.com,reader,\n"
                       "u@example.com,f3,int.doc,doc,1,u@example.com,"
                       "user,in@example.com,example.com,reader,")
        findings = {f.fid: f for f in ts.check_external_file_shares(self.ctx)}
        self.assertIn("external-user-shares", findings)
        self.assertIn("external-domain-shares", findings)
        self.assertEqual(1, len(findings["external-user-shares"].evidence))
        self.assertEqual(["dom.doc"], [e["File"] for e in
                                       findings["external-domain-shares"].evidence])
        self.assertEqual("MEDIUM", findings["external-user-shares"].severity)
        self.assertEqual("HIGH", findings["external-domain-shares"].severity)
        aud = findings["target-audience-shares"]
        self.assertEqual("INFO", aud.severity)
        self.assertEqual([{"Audience ID": "c03abc", "Files": "1",
                           "Example file": "aud.doc",
                           "Owner": "u@example.com"}], aud.evidence)

    def test_anyone_rows_not_double_reported(self):
        # anyone-type ACLs belong to check_public_files, not this check.
        self.write_csv("mydrive_external", self.MYDRIVE_HEADER + "\n"
                       "u@example.com,f1,pub.doc,doc,1,u@example.com,"
                       "anyone,,,reader,True")
        self.assertEqual([], ts.check_external_file_shares(self.ctx))

    def test_inbound_shares_are_info(self):
        self.write_csv("sharedwithme_external",
                       "Owner,id,name,owners,owners.0.emailAddress,"
                       "sharedWithMeTime\n"
                       "u@example.com,f9,inbound.txt,1,ext@other.com,"
                       "2026-08-15T15:38:35Z")
        findings = ts.check_external_file_shares(self.ctx)
        self.assertEqual(["external-inbound-shares"],
                         self.finding_ids(findings))
        self.assertEqual("INFO", findings[0].severity)


class TestGroupChecks(CtxTestCase):
    GROUPS_HEADER = ("email,name,directMembersCount,whoCanJoin,"
                     "allowExternalMembers,whoCanPostMessage")

    def test_anyone_can_join(self):
        self.write_csv("groups", f"""{self.GROUPS_HEADER}
open@example.com,Open,3,ANYONE_CAN_JOIN,false,ALL_MEMBERS_CAN_POST""")
        ids = self.finding_ids(ts.check_group_exposure(self.ctx))
        self.assertEqual(["groups-anyone-join"], ids)

    def test_external_members_and_open_post(self):
        self.write_csv("groups", f"""{self.GROUPS_HEADER}
ext@example.com,Ext,3,INVITED_CAN_JOIN,true,ANYONE_CAN_POST""")
        ids = self.finding_ids(ts.check_group_exposure(self.ctx))
        self.assertEqual(["groups-external-members", "groups-anyone-post"],
                         ids)

    def test_locked_group_clean(self):
        self.write_csv("groups", f"""{self.GROUPS_HEADER}
safe@example.com,Safe,3,INVITED_CAN_JOIN,false,ALL_MEMBERS_CAN_POST""")
        self.assertEqual([], ts.check_group_exposure(self.ctx))

    def test_public_archive_high_and_discoverable_info(self):
        self.write_csv("groups", f"""{self.GROUPS_HEADER},whoCanViewGroup,whoCanDiscoverGroup
pub@example.com,Pub,3,INVITED_CAN_JOIN,false,ALL_MEMBERS_CAN_POST,ANYONE_CAN_VIEW,ANYONE_CAN_DISCOVER
safe@example.com,Safe,3,INVITED_CAN_JOIN,false,ALL_MEMBERS_CAN_POST,ALL_MEMBERS_CAN_VIEW,ALL_IN_DOMAIN_CAN_DISCOVER""")
        findings = {f.fid: f for f in ts.check_group_exposure(self.ctx)}
        self.assertEqual({"groups-public-archive", "groups-discoverable"},
                         set(findings))
        self.assertEqual("HIGH", findings["groups-public-archive"].severity)
        self.assertEqual(1, findings["groups-discoverable"].count)

    def test_members_external_ownerless_and_suspended_owner(self):
        self.write_csv("users", f"""{USERS_HEADER}
gone@example.com,True,False,2026-01-01T10:00:00Z,True,True,,False,False,Business
here@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Business""")
        self.write_csv("groups", f"""{self.GROUPS_HEADER}
a@example.com,A,3,INVITED_CAN_JOIN,true,ALL_MEMBERS_CAN_POST
b@example.com,B,1,INVITED_CAN_JOIN,false,ALL_MEMBERS_CAN_POST
c@example.com,C,1,INVITED_CAN_JOIN,false,ALL_MEMBERS_CAN_POST
classroom_teachers@example.com,Classroom Teachers,0,INVITED_CAN_JOIN,false,ALL_MEMBERS_CAN_POST""")
        # classroom_teachers@ is Classroom's own ownerless group: never flagged.
        self.write_csv("group_members", """group,type,role,status,email
a@example.com,USER,OWNER,ACTIVE,gone@example.com
a@example.com,USER,MEMBER,,outsider@gmail.com
b@example.com,USER,MEMBER,ACTIVE,here@example.com
c@example.com,USER,OWNER,ACTIVE,here@example.com
c@example.com,CUSTOMER,MEMBER,,""")
        findings = {f.fid: f for f in ts.check_group_members(self.ctx)}
        self.assertEqual({"groups-external-members-present",
                          "groups-no-owner", "groups-suspended-owner"},
                         set(findings))
        self.assertEqual("outsider@gmail.com",
                         findings["groups-external-members-present"]
                         .evidence[0]["External member"])
        self.assertEqual(["b@example.com"],
                         [r["Group"] for r in findings["groups-no-owner"].evidence])
        self.assertEqual("gone@example.com",
                         findings["groups-suspended-owner"].evidence[0]["Owner"])


class TestMailboxSettingsChecks(CtxTestCase):
    """Round 9: sendas, forwarding addresses and vacation, collected since
    v1.0.0 and read by nothing."""

    def test_external_sendas_flagged_primary_and_internal_not(self):
        self.write_csv("sendas", """User,displayName,sendAsEmail,replyToAddress,isPrimary,isDefault,treatAsAlias,verificationStatus
a@example.com,,a@example.com,,True,True,,
a@example.com,,a.alias@alias.example.com,,False,False,True,accepted
b@example.com,,b@gmail.com,,False,False,False,pending""")
        findings = ts.check_sendas(self.ctx)
        self.assertEqual(["sendas-external"], self.finding_ids(findings))
        self.assertEqual([{"User": "b@example.com", "Sends as": "b@gmail.com",
                           "Verified": "pending", "Reply-to": ""}],
                         findings[0].evidence)

    def test_external_forwarding_address_on_file(self):
        self.write_csv("forwardingaddresses", """User,forwardingEmail,verificationStatus
a@example.com,a.home@gmail.com,accepted
b@example.com,b@alias.example.com,accepted""")
        findings = ts.check_forwarding_addresses(self.ctx)
        self.assertEqual(["forwarding-addresses-external"],
                         self.finding_ids(findings))
        self.assertEqual("a.home@gmail.com",
                         findings[0].evidence[0]["Forwarding address"])

    def test_vacation_to_anyone_only(self):
        self.write_csv("vacation", """User,enabled,contactsonly,domainonly,startdate,enddate,subject
a@example.com,True,False,False,,,Away
b@example.com,True,True,False,,,Away
c@example.com,False,False,False,,,Away""")
        findings = ts.check_vacation(self.ctx)
        self.assertEqual(["vacation-replies-to-anyone"], self.finding_ids(findings))
        self.assertEqual([{"User": "a@example.com", "Subject": "Away",
                           "Ends": "no end date"}], findings[0].evidence)


class TestRound9UserChecks(CtxTestCase):
    HEADER = USERS_HEADER + ",suspensionReason,creationTime,orgUnitPath,recoveryPhone"

    def test_google_suspended_not_admin_suspended(self):
        self.write_csv("users", f"""{self.HEADER}
leaver@example.com,True,False,2026-01-01T10:00:00Z,True,True,,False,False,Business,ADMIN,2025-01-01T00:00:00Z,/,
hacked@example.com,True,False,2026-01-01T10:00:00Z,True,True,,False,False,Business,ABUSE,2025-01-01T00:00:00Z,/,""")
        findings = ts.check_google_suspended(self.ctx)
        self.assertEqual(["google-suspended-accounts"], self.finding_ids(findings))
        self.assertEqual([{"User": "hacked@example.com", "Reason": "ABUSE"}],
                         findings[0].evidence)

    def test_new_accounts_within_window(self):
        recent = (ts.datetime.now(ts.timezone.utc)
                  - ts.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.write_csv("users", f"""{self.HEADER}
old@example.com,False,False,2026-01-01T10:00:00Z,True,True,,False,False,Business,,2020-01-01T00:00:00Z,/Staff,
new@example.com,False,False,,False,False,,True,False,Business,,{recent},/,""")
        findings = ts.check_new_accounts(self.ctx)
        self.assertEqual(["new-accounts"], self.finding_ids(findings))
        self.assertEqual("new@example.com", findings[0].evidence[0]["User"])
        self.assertEqual("super admin", findings[0].evidence[0]["Admin"])

    def test_admin_enrolled_but_not_enforced(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,False,,True,False,Business
boss2@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business
boss3@example.com,False,False,2026-08-01T10:00:00Z,False,False,,True,False,Business""")
        findings = ts.check_admin_2sv_enforced(self.ctx)
        self.assertEqual([{"Super admin": "boss@example.com"}],
                         findings[0].evidence)

    def test_admin_recovery_phone_masked(self):
        self.write_csv("users", f"""{self.HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business,,2020-01-01T00:00:00Z,/,+27821234567""")
        findings = ts.check_admin_recovery(self.ctx)
        self.assertEqual(["admin-personal-recovery"], self.finding_ids(findings))
        self.assertEqual("...4567", findings[0].evidence[0]["Recovery phone"])
        self.assertNotIn("27821234567", json.dumps(findings[0].evidence))

    def test_root_ou_users_only_when_other_ous_exist(self):
        self.write_csv("users", f"""{self.HEADER}
root@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Business,,2020-01-01T00:00:00Z,/,
staff@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Business,,2020-01-01T00:00:00Z,/Staff,""")
        self.write_csv("orgs", "orgUnitPath,orgUnitId,name,parentOrgUnitId")
        self.assertEqual([], ts.check_root_ou_users(self.ctx))
        self.write_csv("orgs", """orgUnitPath,orgUnitId,name,parentOrgUnitId
/Staff,id:1,Staff,id:0""")
        findings = ts.check_root_ou_users(self.ctx)
        self.assertEqual(["root@example.com"],
                         [r["User"] for r in findings[0].evidence])

    def test_weak_passwords_from_usage_report_live_users_only(self):
        self.write_csv("users", f"""{USERS_HEADER}
weak@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Business
short@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Business
gone@example.com,True,False,2026-08-01T10:00:00Z,True,True,,False,False,Business
boss@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business""")
        self.write_csv("report_users", """email,date,accounts:password_strength,accounts:password_length_compliance,accounts:num_security_keys,accounts:num_passkeys_enrolled
weak@example.com,2026-08-13,WEAK,COMPLIANT,0,0
short@example.com,2026-08-13,STRONG,NON_COMPLIANT,0,0
gone@example.com,2026-08-13,WEAK,NON_COMPLIANT,0,0
boss@example.com,2026-08-13,STRONG,COMPLIANT,2,1
never@example.com,2026-08-13,UNKNOWN,UNKNOWN,0,0""")
        findings = ts.check_user_password_strength(self.ctx)
        self.assertEqual(["weak-user-passwords"], self.finding_ids(findings))
        self.assertEqual({"weak@example.com": "weak password",
                          "short@example.com": "shorter than the policy minimum"},
                         {r["User"]: r["Problem"] for r in findings[0].evidence})
        second = ts.check_admin_second_factors(self.ctx)
        self.assertEqual(["admin-second-factors"], self.finding_ids(second))
        self.assertEqual([{"Super admin": "boss@example.com",
                           "Security keys": "2", "Passkeys": "1",
                           "2SV enrolled": "True"}], second[0].evidence)

    def test_admin_with_only_codes_is_not_phish_resistant(self):
        self.write_csv("users", f"""{USERS_HEADER}
app@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business
key@example.com,False,False,2026-08-01T10:00:00Z,True,True,,True,False,Business
no2sv@example.com,False,False,2026-08-01T10:00:00Z,False,False,,True,False,Business""")
        self.write_csv("report_users", """email,accounts:num_security_keys,accounts:num_passkeys_enrolled
app@example.com,0,0
key@example.com,1,0
no2sv@example.com,0,0""")
        found = {f.fid: f for f in ts.check_admin_second_factors(self.ctx)}
        # no2sv already has its own CRITICAL finding; not repeated here.
        self.assertEqual([{"Super admin": "app@example.com"}],
                         found["admins-not-phish-resistant"].evidence)
        self.assertEqual("MEDIUM", found["admins-not-phish-resistant"].severity)


class TestRound9DriveAndVault(CtxTestCase):
    def test_vault_exports_listed(self):
        self.write_csv("vaultexports", """matterId,matterName,id,name,createTime
m1,Litigation 2026,e1,All mail 2026,2026-08-01T00:00:00Z""")
        findings = ts.check_vault_exports(self.ctx)
        self.assertEqual(["vault-exports"], self.finding_ids(findings))
        self.assertEqual("Litigation 2026", findings[0].evidence[0]["Matter"])

    def test_shared_drive_copy_download_open(self):
        self.write_csv("shareddrives", """id,name,restrictions.copyRequiresWriterPermission,restrictions.downloadRestriction.restrictedForReaders
d1,Open,False,False
d2,Locked,True,True
d3,Unknown,,""")
        findings = ts.check_shared_drive_download_controls(self.ctx)
        self.assertEqual(["sd-download-copy-open"], self.finding_ids(findings))
        self.assertEqual(["Open"],
                         [r["Shared Drive"] for r in findings[0].evidence])

    def test_tenant_shape_counts_orgs_and_sites(self):
        self.write_csv("orgs", """orgUnitPath,orgUnitId,name,parentOrgUnitId
/Staff,id:1,Staff,id:0""")
        self.write_csv("sites", """Owner,id,name
a@example.com,s1,Intranet""")
        facts = {r["Fact"]: r["Value"]
                 for r in ts.check_tenant_shape(self.ctx)[0].evidence}
        self.assertEqual("1", facts["Organisational units (below root)"])
        self.assertEqual("1", facts["Google Sites"])


class TestAccountHygieneChecks(CtxTestCase):
    def test_2sv_enrolment_percentage(self):
        self.write_csv("users", f"""{USERS_HEADER}
a@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Business
b@example.com,False,False,2026-08-01T10:00:00Z,False,False,,False,False,Business""")
        findings = ts.check_2sv_enrolment(self.ctx)
        self.assertEqual(["2sv-enrolment"], self.finding_ids(findings))
        self.assertIn("50%", findings[0].title)

    def test_full_2sv_clean(self):
        self.write_csv("users", f"""{USERS_HEADER}
a@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Business""")
        self.assertEqual([], ts.check_2sv_enrolment(self.ctx))

    def test_pop_imap_enabled(self):
        self.write_csv("imap", """User,enabled
a@example.com,True""")
        self.write_csv("pop", """User,enabled
a@example.com,False""")
        ids = self.finding_ids(ts.check_pop_imap(self.ctx))
        self.assertEqual(["imap-enabled"], ids)

    def test_dormant_tiers_split(self):
        self.write_csv("users", f"""{USERS_HEADER}
old@example.com,False,False,2024-01-01T10:00:00Z,True,True,,False,False,Business
never@example.com,False,False,Never,True,True,,False,False,Business
epoch@example.com,False,False,1970-01-01T00:00:00.000Z,True,True,,False,False,Business
fresh@example.com,False,False,2026-08-14T10:00:00Z,True,True,,False,False,Business
unlicensed@example.com,False,False,Never,True,True,,False,False,""")
        findings = ts.check_dormant_accounts(self.ctx)
        by_id = {f.fid: f for f in findings}
        self.assertEqual({"never-logged-in", "dormant-licensed"},
                         set(by_id))
        self.assertEqual(["never@example.com", "epoch@example.com"],
                         [r["User"] for r in by_id["never-logged-in"].evidence])
        self.assertEqual(["old@example.com"],
                         [r["User"] for r in by_id["dormant-licensed"].evidence])

    def test_dormant_admin_is_high_even_unlicensed(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-14T10:00:00Z,True,True,,True,False,Business
oldadmin@example.com,False,False,2024-01-01T10:00:00Z,True,True,,False,True,""")
        findings = ts.check_dormant_accounts(self.ctx)
        self.assertEqual(["dormant-admin"], self.finding_ids(findings))
        self.assertEqual("HIGH", findings[0].severity)
        self.assertEqual("delegated admin",
                         findings[0].evidence[0]["Admin role"])

    def test_unmanaged_accounts(self):
        self.write_csv("userinvitations", """email,state,updateTime
rogue@example.com,NOT_YET_SENT,2026-08-01T00:00:00Z""")
        ids = self.finding_ids(ts.check_unmanaged_accounts(self.ctx))
        self.assertEqual(["unmanaged-accounts"], ids)


class TestDelegationChecks(CtxTestCase):
    def test_admin_mailbox_delegate_is_high_and_map_emitted(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-14T10:00:00Z,True,True,,True,False,Business
pa@example.com,False,False,2026-08-14T10:00:00Z,True,True,,False,False,Business""")
        self.write_csv("delegates", """User,delegateAddress,delegationStatus
boss@example.com,pa@example.com,ACCEPTED""")
        findings = ts.check_mailbox_delegation(self.ctx)
        ids = self.finding_ids(findings)
        self.assertIn("delegates-on-admin-mailbox", ids)
        self.assertIn("delegation-map", ids)
        self.assertNotIn("delegation-unwatched", ids)

    def test_suspended_delegate_is_medium(self):
        self.write_csv("users", f"""{USERS_HEADER}
owner@example.com,False,False,2026-08-14T10:00:00Z,True,True,,False,False,Business
gone@example.com,True,False,2026-08-14T10:00:00Z,True,True,,False,False,Business""")
        self.write_csv("delegates", """User,delegateAddress,delegationStatus
owner@example.com,gone@example.com,ACCEPTED""")
        findings = ts.check_mailbox_delegation(self.ctx)
        by_id = {f.fid: f for f in findings}
        self.assertIn("delegation-unwatched", by_id)
        self.assertIn("delegate suspended",
                      by_id["delegation-unwatched"].evidence[0]["Why"])
        self.assertNotIn("delegates-on-admin-mailbox", by_id)

    def test_delegated_admin_mailbox_also_high(self):
        self.write_csv("users", f"""{USERS_HEADER}
helpdesk@example.com,False,False,2026-08-14T10:00:00Z,True,True,,False,True,Business
pa@example.com,False,False,2026-08-14T10:00:00Z,True,True,,False,False,Business""")
        self.write_csv("delegates", """User,delegateAddress,delegationStatus
helpdesk@example.com,pa@example.com,ACCEPTED""")
        findings = ts.check_mailbox_delegation(self.ctx)
        by_id = {f.fid: f for f in findings}
        self.assertIn("delegates-on-admin-mailbox", by_id)
        self.assertEqual("delegated admin",
                         by_id["delegates-on-admin-mailbox"]
                         .evidence[0]["Admin role"])

    def test_plain_delegation_only_info(self):
        self.write_csv("users", f"""{USERS_HEADER}
owner@example.com,False,False,2026-08-14T10:00:00Z,True,True,,False,False,Business
pa@example.com,False,False,2026-08-14T10:00:00Z,True,True,,False,False,Business""")
        self.write_csv("delegates", """User,delegateAddress,delegationStatus
owner@example.com,pa@example.com,ACCEPTED""")
        self.assertEqual(["delegation-map"],
                         self.finding_ids(ts.check_mailbox_delegation(self.ctx)))


class TestAtRiskComposite(CtxTestCase):
    def test_two_factors_flagged_one_not(self):
        # risky: no 2SV + personal recovery. clean: 2SV on, no other factor.
        self.write_csv("users", f"""{USERS_HEADER}
risky@example.com,False,False,2026-08-14T10:00:00Z,False,False,risky@gmail.com,False,False,Business
clean@example.com,False,False,2026-08-14T10:00:00Z,True,True,it@example.com,False,False,Business""")
        findings = ts.check_at_risk_accounts(self.ctx)
        self.assertEqual(["at-risk-accounts"], self.finding_ids(findings))
        self.assertEqual("MEDIUM", findings[0].severity)
        self.assertEqual(["risky@example.com"],
                         [r["User"] for r in findings[0].evidence])

    def test_admin_in_list_raises_to_high(self):
        # No 2SV + personal recovery on an admin: HIGH. The admin role is
        # not itself a factor (the admin-no-2sv CRITICAL already names them),
        # so an admin with one weakness is not listed.
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-14T10:00:00Z,False,False,boss@gmail.com,True,False,Business
boss2@example.com,False,False,2026-08-14T10:00:00Z,False,False,it@example.com,True,False,Business""")
        findings = ts.check_at_risk_accounts(self.ctx)
        self.assertEqual("HIGH", findings[0].severity)
        self.assertEqual(["boss@example.com"],
                         [r["User"] for r in findings[0].evidence])
        self.assertNotIn("admin role", findings[0].evidence[0]["Risk factors"])

    def test_asps_and_risky_token_count_as_factors(self):
        self.write_csv("users", f"""{USERS_HEADER}
u@example.com,False,False,2026-08-14T10:00:00Z,True,True,it@example.com,False,False,Business""")
        self.write_csv("asps", """User,codeId,name,creationTime
u@example.com,1,Old mail app,2025-01-01T00:00:00Z""")
        self.write_csv("tokens", """user,clientId,displayText,scopes
u@example.com,c1,Got Your Back,https://mail.google.com/ openid""")
        findings = ts.check_at_risk_accounts(self.ctx)
        factors = findings[0].evidence[0]["Risk factors"]
        self.assertIn("app-specific passwords", factors)
        self.assertIn("app with full mail/Drive access", factors)

    def test_single_factor_clean(self):
        self.write_csv("users", f"""{USERS_HEADER}
u@example.com,False,False,2026-08-14T10:00:00Z,False,False,it@example.com,False,False,Business""")
        self.assertEqual([], ts.check_at_risk_accounts(self.ctx))


class TestSuspendedHoldingData(CtxTestCase):
    def test_suspended_licensed_and_data_footprint(self):
        self.write_csv("users", f"""{USERS_HEADER}
gone@example.com,True,False,2024-01-01T10:00:00Z,True,True,,False,False,Business""")
        self.write_csv("report_users", """email,accounts:gmail_used_quota_in_mb,accounts:drive_used_quota_in_mb
gone@example.com,1024,2048
here@example.com,10,10""")
        self.write_csv("shareddriveacls", """User,id,name,permission.emailAddress,permission.role,permission.deleted
admin@example.com,SD1,Finance,gone@example.com,organizer,False""")
        findings = ts.check_suspended_holding_data(self.ctx)
        by_id = {f.fid: f for f in findings}
        self.assertEqual({"suspended-licensed", "suspended-holding-data"},
                         set(by_id))
        holds = [r["Holds"] for r in by_id["suspended-holding-data"].evidence]
        self.assertIn("mailbox/Drive data", holds)
        self.assertIn('manager of Shared Drive "Finance"', holds)

    def test_unlicensed_suspended_reader_is_quiet(self):
        self.write_csv("users", f"""{USERS_HEADER}
gone@example.com,True,False,2024-01-01T10:00:00Z,True,True,,False,False,""")
        self.write_csv("report_users", """email,accounts:gmail_used_quota_in_mb,accounts:drive_used_quota_in_mb
gone@example.com,0,0""")
        self.write_csv("shareddriveacls", """User,id,name,permission.emailAddress,permission.role,permission.deleted
admin@example.com,SD1,Finance,gone@example.com,reader,False""")
        self.assertEqual([], ts.check_suspended_holding_data(self.ctx))

    def test_cloud_identity_only_is_not_licensed(self):
        # Free Cloud Identity auto-assigns; it must not count as a paid seat
        # for the suspended-licensed or dormancy findings. Premium must.
        self.write_csv("users", f"""{USERS_HEADER}
bob@example.com,True,False,Never,True,True,,False,False,Cloud Identity
prem@example.com,True,False,Never,True,True,,False,False,Cloud Identity Premium
mix@example.com,False,False,Never,True,True,,False,False,Cloud Identity Google Workspace Enterprise Plus (formerly G Suite Enterprise)""")
        findings = ts.check_suspended_holding_data(self.ctx)
        by_id = {f.fid: f for f in findings}
        self.assertEqual(["prem@example.com"],
                         [r["User"] for r in by_id["suspended-licensed"].evidence])
        dormant = ts.check_dormant_accounts(self.ctx)
        by_id = {f.fid: f for f in dormant}
        self.assertEqual(["mix@example.com"],
                         [r["User"] for r in by_id["never-logged-in"].evidence])

    def test_no_suspended_users_no_findings(self):
        self.write_csv("users", f"""{USERS_HEADER}
here@example.com,False,False,2026-08-14T10:00:00Z,True,True,,False,False,Business""")
        self.assertEqual([], ts.check_suspended_holding_data(self.ctx))


class TestOAuthTokenCheck(CtxTestCase):
    def test_full_mail_scope_flagged_and_ranked(self):
        self.write_csv("tokens", """user,clientId,displayText,scopes
a@example.com,c1,Got Your Back,https://mail.google.com/ openid
b@example.com,c1,Got Your Back,https://mail.google.com/
c@example.com,c2,Nice App,https://www.googleapis.com/auth/drive.readonly""")
        findings = ts.check_risky_oauth(self.ctx)
        self.assertEqual(["risky-oauth-apps"], self.finding_ids(findings))
        self.assertEqual("Got Your Back", findings[0].evidence[0]["App"])
        self.assertEqual("2", findings[0].evidence[0]["Users"])

    def test_scopes_match_whole_tokens_and_readonly_is_risky(self):
        # .../auth/drive must be matched as a whole token, not a prefix of
        # .../auth/drive.file (not risky). drive.readonly IS risky since
        # round 9: reading everything is the exposure.
        self.write_csv("tokens", """user,clientId,displayText,scopes
a@example.com,c2,Nice App,https://www.googleapis.com/auth/drive.file
b@example.com,c4,Reader,https://www.googleapis.com/auth/drive.readonly""")
        findings = ts.check_risky_oauth(self.ctx)
        self.assertEqual(["Reader"], [r["App"] for r in findings[0].evidence])
        self.assertEqual("read all of Drive", findings[0].evidence[0]["Access"])

    def test_app_inventory_puts_unidentified_first(self):
        self.write_csv("tokens", """user,clientId,displayText,anonymous,scopes
a@example.com,c1,Popular,False,openid email
b@example.com,c1,Popular,False,openid email
c@example.com,c9,,True,openid""")
        findings = ts.check_oauth_inventory(self.ctx)
        self.assertEqual(["oauth-app-map"], self.finding_ids(findings))
        self.assertEqual(2, findings[0].count)
        self.assertEqual("c9", findings[0].evidence[0]["App"])
        self.assertEqual("yes", findings[0].evidence[0]["Unidentified"])
        self.assertIn("1 unidentified", findings[0].title)

    def test_full_drive_scope_flagged(self):
        self.write_csv("tokens", """user,clientId,displayText,scopes
a@example.com,c3,Greedy App,https://www.googleapis.com/auth/drive openid""")
        findings = ts.check_risky_oauth(self.ctx)
        self.assertEqual(1, len(findings))


class TestCalendarCheck(CtxTestCase):
    def test_public_calendar_default_scope(self):
        self.write_csv("calendaracls", """primaryEmail,calendarId,role,scope.type,scope.value
a@example.com,a@example.com,reader,default,""")
        ids = self.finding_ids(ts.check_public_calendars(self.ctx))
        self.assertEqual(["public-calendars"], ids)

    def test_domain_reader_is_not_a_finding(self):
        # A domain-wide reader row is the tenant default sharing state.
        self.write_csv("calendaracls", """primaryEmail,calendarId,role,scope.type,scope.value
a@example.com,a@example.com,reader,domain,example.com""")
        self.assertEqual([], ts.check_public_calendars(self.ctx))


class TestDnsCheck(CtxTestCase):
    def setUp(self):
        super().setUp()
        # The check is gated on the module like every other one: a dns.json
        # left by a failed collection must not read as "DNS is fine".
        self.ctx.set_module("dns", "ok", 2)

    def test_dmarc_missing_via_doh(self):
        (self.run_dir / "dns.json").write_text(json.dumps({
            "example.com": {"path": "doh", "checks": {
                "mx": {"present": True}, "spf": {"present": True},
                "dkim": {"present": True}, "dmarc": {"present": False}}},
            "alias.example.com": {"path": "doh", "checks": {
                "dmarc": {"present": True}}},
        }), encoding="utf-8")
        findings = ts.check_dns_findings(self.ctx)
        self.assertEqual(["dmarc-missing"], self.finding_ids(findings))
        self.assertEqual(1, findings[0].count)

    def test_no_dns_file_no_finding(self):
        self.assertEqual([], ts.check_dns_findings(self.ctx))

    def test_tamingdns_info_findings_are_not_missing(self):
        # Org-domain inheritance and deprecated-tag notes come back as
        # info-severity findings with status "warn"; that is a present DMARC.
        (self.run_dir / "dns.json").write_text(json.dumps({
            "example.com": {"path": "tamingdns", "checks": {
                "dmarc": {"status": "warn", "findings": [
                    {"severity": "info",
                     "title": "DMARC inherited from organisational domain"}]}}},
        }), encoding="utf-8")
        self.assertEqual([], ts.check_dns_findings(self.ctx))

    def test_tamingdns_fail_status_is_missing(self):
        (self.run_dir / "dns.json").write_text(json.dumps({
            "example.com": {"path": "tamingdns", "checks": {
                "dmarc": {"status": "fail", "findings": [
                    {"severity": "critical", "title": "No DMARC record"}]}}},
        }), encoding="utf-8")
        findings = ts.check_dns_findings(self.ctx)
        self.assertEqual(["dmarc-missing"],
                         [f.fid for f in findings])

    def test_missing_spf_as_dev_reported_it(self):
        # Exact shape from dev.osh.co.za on 2026-08-15: nothing above info.
        (self.run_dir / "dns.json").write_text(json.dumps({
            "example.com": {"path": "tamingdns", "checks": {
                "spf": {"status": "info", "grade": "F",
                        "verdict": "not_configured", "findings": [
                            {"severity": "info",
                             "title": "No SPF record published"}]}}},
        }), encoding="utf-8")
        self.assertEqual(["spf-missing"],
                         self.finding_ids(ts.check_dns_findings(self.ctx)))

    def test_spf_dkim_mx_each_get_their_own_finding(self):
        # Dev on 2026-08-15: SPF graded F with a critical finding, DKIM
        # pass, DMARC warn/info. Before this only DMARC could ever fire.
        (self.run_dir / "dns.json").write_text(json.dumps({
            "example.com": {"path": "tamingdns", "checks": {
                "mx": {"status": "fail", "findings": [
                    {"severity": "high", "title": "No MX records"}]},
                "spf": {"status": "info", "grade": "F", "findings": [
                    {"severity": "critical", "title": "No SPF record"}]},
                "dkim": {"status": "pass", "findings": []},
                "dmarc": {"status": "warn", "findings": [
                    {"severity": "info", "title": "inherited"}]}}},
            "alias.example.com": {"path": "doh", "checks": {
                "mx": {"present": True}, "spf": {"present": True},
                "dkim": {"present": False}, "dmarc": {"present": True}}},
        }), encoding="utf-8")
        findings = {f.fid: f for f in ts.check_dns_findings(self.ctx)}
        self.assertEqual({"spf-missing", "dkim-missing", "mx-problem"},
                         set(findings))
        self.assertEqual("HIGH", findings["spf-missing"].severity)
        self.assertEqual("alias.example.com",
                         findings["dkim-missing"].evidence[0]["Domain"])
        self.assertEqual("dns.google",
                         findings["dkim-missing"].evidence[0]["Checked via"])


import csv as _csv


class PolicyTestCase(CtxTestCase):
    """Check-logic tests over hand-built partial policies. Google's defaults
    are switched off here, or every missing field would take its default;
    TestPolicyDefaults covers them."""
    defaults_file = None

    def setUp(self):
        super().setUp()
        original = ts.POLICY_DEFAULTS_FILE
        ts.POLICY_DEFAULTS_FILE = (self.defaults_file
                                   or self.run_dir / "no-defaults.json")
        self.addCleanup(setattr, ts, "POLICY_DEFAULTS_FILE", original)

    def write_policies(self, settings, broken_rows=()):
        """settings: list of (type, orgUnitPath, value-dict) or
        (type, orgUnitPath, value-dict, sortOrder). Writes a policies.csv
        shaped like gam's formatjson output. Real sortOrders: ~101.x for
        Google's SYSTEM defaults, ~201.x for admin-set policies."""
        path = self.run_dir / "policies.csv"
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = _csv.writer(fh)
            writer.writerow(["name", "JSON"])
            for i, entry in enumerate(settings):
                stype, ou, value = entry[:3]
                order = entry[3] if len(entry) > 3 else 101.0
                writer.writerow([f"policies/p{i}", json.dumps(
                    {"policyQuery": {"orgUnitPath": ou,
                                     "sortOrder": order},
                     "setting": {"type": f"settings/{stype}",
                                 "value": value}})])
            for i, raw in enumerate(broken_rows):
                writer.writerow([f"policies/broken{i}", raw])
        self.ctx.set_module("policies", "ok", len(settings))


class TestPolicyParsing(PolicyTestCase):
    def test_licence_scoped_duplicates_collapse(self):
        value = {"minimumLength": 8}
        self.write_policies([("security.password", "/", value)] * 3)
        parsed = ts._policy_settings(self.ctx)
        self.assertEqual(1, len(parsed))
        self.assertEqual("security.password", parsed[0]["type"])

    def test_highest_sort_order_wins(self):
        # The admin-set policy (201.x) beats Google's SYSTEM default
        # (101.x) for the same setting and OU - one resolved row, not two.
        self.write_policies([
            ("security.password", "/", {"minimumLength": 8}, 101.00073),
            ("security.password", "/", {"minimumLength": 14}, 201.0031)])
        parsed = ts._policy_settings(self.ctx)
        self.assertEqual(1, len(parsed))
        self.assertEqual(14, parsed[0]["value"]["minimumLength"])

    def test_admin_policy_suppresses_weak_default_finding(self):
        # Kim Nilsson's report: root / returns several security.password
        # policies, and reading the SYSTEM default row flagged a tenant
        # whose admin had already hardened the policy.
        self.write_policies([
            ("security.password", "/",
             {"minimumLength": 8, "allowedStrength": "STRONG"}, 101.00073),
            ("security.password", "/",
             {"minimumLength": 8, "allowedStrength": "STRONG"}, 101.00106),
            ("security.password", "/",
             {"minimumLength": 14, "allowedStrength": "STRONG"}, 201.0031)])
        self.assertEqual([], ts.check_password_policy(self.ctx))

    def test_fields_merge_across_policies(self):
        # Max reduces per field: a partial high-order policy overrides only
        # the fields it carries.
        self.write_policies([
            ("security.password", "/",
             {"minimumLength": 8, "allowReuse": False}, 101.0),
            ("security.password", "/", {"minimumLength": 12}, 201.0)])
        value = ts._policy_settings(self.ctx)[0]["value"]
        self.assertEqual(12, value["minimumLength"])
        self.assertIs(False, value["allowReuse"])

    def test_per_ou_policies_stay_separate(self):
        self.write_policies([
            ("security.password", "/", {"minimumLength": 14}, 201.0),
            ("security.password", "/Contractors",
             {"minimumLength": 8}, 202.0)])
        parsed = ts._policy_settings(self.ctx)
        self.assertEqual({"/", "/Contractors"}, {p["ou"] for p in parsed})

    def test_rule_rows_not_reduced(self):
        # DLP rules and system-defined alerts are a list, not one setting.
        self.write_policies([
            ("rule.dlp", "/", {"name": "one"}),
            ("rule.dlp", "/", {"name": "two"})])
        self.assertEqual(2, len(ts._policy_settings(self.ctx)))

    def test_gam_backslash_quote_artifact_repaired(self):
        # gam formatjson renders a quote inside a DLP rule name as \\",
        # which is invalid JSON after CSV decoding; the parser repairs it.
        broken = ('{"setting": {"type": "settings/rule.dlp", "value": '
                  '{"name": "contains \\\\"Credit card\\\\" data"}}, '
                  '"policyQuery": {"orgUnitPath": "/"}}')
        self.write_policies(
            [("security.password", "/", {"minimumLength": 8})],
            broken_rows=[broken])
        parsed = ts._policy_settings(self.ctx)
        types = {p["type"] for p in parsed}
        self.assertIn("security.password", types)
        self.assertIn("rule.dlp", types)

    def test_unparseable_row_skipped_not_fatal(self):
        self.write_policies(
            [("security.password", "/", {"minimumLength": 8})],
            broken_rows=["{this is not json at all"])
        self.assertEqual(1, len(ts._policy_settings(self.ctx)))


class TestPolicyDefaults(PolicyTestCase):
    defaults_file = ts.POLICY_DEFAULTS_FILE

    def by_type(self):
        return {(p["type"], p["ou"]): p for p in ts._policy_settings(self.ctx)}

    def test_shipped_defaults_file_loads(self):
        data = json.loads(ts.POLICY_DEFAULTS_FILE.read_text(encoding="utf-8"))
        self.assertTrue(data["defaults"]["gmail.auto_forwarding"][
            "enableAutoForwarding"])

    def test_missing_setting_takes_google_default_at_root_only(self):
        self.write_policies([("gmail.auto_forwarding", "/Sales",
                              {"enableAutoForwarding": False}, 201.0)])
        got = self.by_type()
        root = got[("gmail.auto_forwarding", "/")]
        self.assertIs(True, root["value"]["enableAutoForwarding"])
        self.assertEqual(["enableAutoForwarding"], root["defaulted"])
        # A child org unit's own value is never overwritten.
        sales = got[("gmail.auto_forwarding", "/Sales")]
        self.assertIs(False, sales["value"]["enableAutoForwarding"])
        self.assertNotIn("defaulted", sales)

    def test_admin_value_is_kept_and_only_gaps_filled(self):
        self.write_policies([("drive_and_docs.external_sharing", "/",
                              {"allowPublishingFiles": False}, 201.0)])
        root = self.by_type()[("drive_and_docs.external_sharing", "/")]
        self.assertIs(False, root["value"]["allowPublishingFiles"])
        self.assertNotIn("allowPublishingFiles", root["defaulted"])
        self.assertEqual("ALLOWED", root["value"]["externalSharingMode"])

    def test_baseline_names_default_and_admin_values(self):
        self.write_policies([("api_controls.internal_apps", "/",
                              {"trustInternalApps": True}, 201.0)])
        found = {f.fid: f for f in ts.check_policy_baseline(self.ctx)}
        rows = {r["Setting"]: r for r in found["policy-baseline"].evidence}
        self.assertEqual("admin", rows[
            "Apps built inside the organisation are trusted without review"][
            "Set by"])
        fwd = rows["Users can set up automatic forwarding to outside "
                   "addresses"]
        self.assertEqual(("Google default", "GWS.GMAIL.11.1"),
                         (fwd["Set by"], fwd["CISA baseline"]))

    def test_baseline_clean_when_tightened(self):
        self.write_policies([
            ("gmail.auto_forwarding", "/", {"enableAutoForwarding": False}, 201.0),
            ("security.two_step_verification_device_trust", "/",
             {"allowTrustingDevice": False}, 201.0)])
        labels = {r["Setting"] for f in ts.check_policy_baseline(self.ctx)
                  for r in f.evidence}
        self.assertNotIn("Users can set up automatic forwarding to outside "
                         "addresses", labels)
        self.assertNotIn("Users can skip 2-step verification on a device they "
                         "mark as trusted", labels)

    def test_marketplace_default_only_on_business_tenants(self):
        self.write_policies([("gmail.auto_forwarding", "/",
                              {"enableAutoForwarding": False}, 201.0)])
        key = ("workspace_marketplace.apps_access_options", "/")
        self.assertEqual("ALLOW_ALL", self.by_type()[key]["value"]["accessLevel"])
        self.ctx._policy_cache = None
        self.write_csv("licenses", "userEmail,skuId,skuDisplay\n"
                       "u@example.com,1010070001,Education Fundamentals")
        self.assertNotIn("accessLevel", self.by_type()[key]["value"])

    def test_flagged_mail_left_in_inbox(self):
        self.write_policies([("gmail.email_attachment_safety", "/", {
            "enableEncryptedAttachmentProtection": True,
            "encryptedAttachmentProtectionConsequence": "WARNING",
            "enableAnomalousAttachmentProtection": True,
            "anomalousAttachmentProtectionConsequence": "SPAM_FOLDER",
            "enableAttachmentWithScriptsProtection": False,
            "attachmentWithScriptsProtectionConsequence": "WARNING"}, 201.0)])
        row = next(r for f in ts.check_policy_baseline(self.ctx)
                   for r in f.evidence if r["CISA baseline"] == "GWS.GMAIL.5.5")
        # Only the protection that is on AND only warns is named.
        self.assertEqual("encryptedAttachmentProtectionConsequence",
                         row["Value"])


class TestPolicyChecks(PolicyTestCase):
    def test_short_minimum_length_flagged(self):
        self.write_policies([("security.password", "/",
                              {"minimumLength": 8, "allowedStrength": "STRONG",
                               "allowReuse": False})])
        findings = ts.check_password_policy(self.ctx)
        self.assertEqual(["password-policy-weak"], self.finding_ids(findings))
        self.assertIn("minimum length is 8",
                      findings[0].evidence[0]["Problem"])

    def test_strong_long_policy_clean(self):
        self.write_policies([("security.password", "/",
                              {"minimumLength": 14, "allowedStrength": "STRONG",
                               "allowReuse": False})])
        self.assertEqual([], ts.check_password_policy(self.ctx))

    def test_session_beyond_default_flagged(self):
        self.write_policies([("security.session_controls", "/",
                              {"webSessionDuration": "2592000s"})])
        findings = ts.check_session_policy(self.ctx)
        self.assertEqual(["session-length"], self.finding_ids(findings))
        self.assertEqual("30 days", findings[0].evidence[0]["Session length"])

    def test_google_default_session_clean(self):
        self.write_policies([("security.session_controls", "/",
                              {"webSessionDuration": "1209600s"})])
        self.assertEqual([], ts.check_session_policy(self.ctx))

    def test_2sv_enrolment_blocked_is_high_and_map_emitted(self):
        self.write_policies([
            ("security.two_step_verification_enrollment", "/Offboarding",
             {"allowEnrollment": False}),
            ("security.two_step_verification_enforcement", "/Offboarding",
             {"enforcedFrom": "1970-01-01T00:00:00Z"})])
        findings = ts.check_2sv_policy(self.ctx)
        by_id = {f.fid: f for f in findings}
        self.assertEqual({"2sv-enrolment-blocked", "2sv-policy-map"},
                         set(by_id))
        self.assertEqual("HIGH", by_id["2sv-enrolment-blocked"].severity)
        self.assertEqual("/Offboarding",
                         by_id["2sv-enrolment-blocked"].evidence[0]["Org unit"])

    def test_2sv_enrolment_allowed_only_map(self):
        self.write_policies([
            ("security.two_step_verification_enrollment", "/",
             {"allowEnrollment": True})])
        self.assertEqual(["2sv-policy-map"],
                         self.finding_ids(ts.check_2sv_policy(self.ctx)))

    def test_shared_drive_default_external_flagged(self):
        self.write_policies([("drive_and_docs.shared_drive_creation", "/",
                              {"allowExternalUserAccess": True,
                               "allowNonMemberAccess": True})])
        findings = ts.check_sharing_policy(self.ctx)
        self.assertEqual(["sd-default-external"], self.finding_ids(findings))

    def test_locked_shared_drive_default_clean(self):
        self.write_policies([("drive_and_docs.shared_drive_creation", "/",
                              {"allowExternalUserAccess": False,
                               "allowNonMemberAccess": False})])
        self.assertEqual([], ts.check_sharing_policy(self.ctx))

    def test_service_status_map_counts_and_lists_disabled(self):
        self.write_policies([
            ("takeout.service_status", "/", {"serviceState": "ENABLED"}),
            ("blogger.service_status", "/", {"serviceState": "DISABLED"})])
        findings = ts.check_service_status(self.ctx)
        self.assertEqual(["service-status"], self.finding_ids(findings))
        self.assertIn("1 enabled, 1 disabled", findings[0].title)
        self.assertEqual("blogger", findings[0].evidence[0]["Service"])

    def test_no_policies_module_no_findings(self):
        for check in (ts.check_password_policy, ts.check_session_policy,
                      ts.check_2sv_policy, ts.check_sharing_policy,
                      ts.check_service_status,
                      ts.check_super_admin_self_recovery,
                      ts.check_gmail_protections, ts.check_external_chat,
                      ts.check_2sv_methods,
                      ts.check_shared_drive_controls,
                      ts.check_policy_settings_raw):
            self.assertEqual([], check(self.ctx))

    def test_super_admin_self_recovery_on_flagged(self):
        # Dev tenant shape: three SYSTEM rows, all true.
        self.write_policies([("security.super_admin_account_recovery", "/",
                              {"enableAccountRecovery": True})] * 3)
        findings = ts.check_super_admin_self_recovery(self.ctx)
        self.assertEqual(["super-admin-self-recovery"],
                         self.finding_ids(findings))
        self.assertEqual(1, len(findings[0].evidence))

    def test_super_admin_self_recovery_admin_off_wins(self):
        self.write_policies([
            ("security.super_admin_account_recovery", "/",
             {"enableAccountRecovery": True}, 101.0),
            ("security.super_admin_account_recovery", "/",
             {"enableAccountRecovery": False}, 201.0)])
        self.assertEqual([], ts.check_super_admin_self_recovery(self.ctx))

    def test_gmail_defaults_flag_only_the_off_switches(self):
        # Values copied from the dev tenant's SYSTEM rows.
        self.write_policies([
            ("gmail.email_attachment_safety", "/",
             {"enableAnomalousAttachmentProtection": False,
              "enableAttachmentWithScriptsProtection": True,
              "enableEncryptedAttachmentProtection": True,
              "applyFutureRecommendedSettingsAutomatically": True}),
            ("gmail.spoofing_and_authentication", "/",
             {"detectDomainNameSpoofing": True, "detectGroupsSpoofing": False,
              "detectUnauthenticatedEmails": False}),
            ("gmail.enhanced_pre_delivery_message_scanning", "/",
             {"enableImprovedSuspiciousContentDetection": True})])
        findings = ts.check_gmail_protections(self.ctx)
        self.assertEqual(["gmail-protections-off"], self.finding_ids(findings))
        labels = {e["Protection"] for e in findings[0].evidence}
        self.assertEqual({
            "Protect against anomalous attachment types in emails",
            "Protect Groups from inbound emails spoofing your domain",
            "Protect against any unauthenticated emails"}, labels)

    def test_gmail_missing_field_is_not_off(self):
        self.write_policies([
            ("gmail.enhanced_pre_delivery_message_scanning", "/", {})])
        self.assertEqual([], ts.check_gmail_protections(self.ctx))

    def test_gmail_admin_override_clears_default(self):
        self.write_policies([
            ("gmail.enhanced_pre_delivery_message_scanning", "/",
             {"enableImprovedSuspiciousContentDetection": False}, 101.0),
            ("gmail.enhanced_pre_delivery_message_scanning", "/",
             {"enableImprovedSuspiciousContentDetection": True}, 201.0)])
        self.assertEqual([], ts.check_gmail_protections(self.ctx))

    def test_external_chat_all_domains_info(self):
        self.write_policies([("chat.chat_external_spaces", "/",
                              {"domainAllowlistMode": "ALL_DOMAINS",
                               "enabled": True})])
        findings = ts.check_external_chat(self.ctx)
        self.assertEqual(["chat-external-open"], self.finding_ids(findings))
        self.assertEqual("INFO", findings[0].severity)

    def test_external_chat_allowlisted_clean(self):
        self.write_policies([("chat.chat_external_spaces", "/",
                              {"domainAllowlistMode": "TRUSTED_DOMAINS",
                               "enabled": True})])
        self.assertEqual([], ts.check_external_chat(self.ctx))

    def test_alert_rules_inactive_flagged_active_ignored(self):
        self.write_policies([
            ("rule.system_defined_alerts", "/",
             {"displayName": "User granted Admin privilege",
              "state": "INACTIVE", "action": {"alertCenterAction": {}}}),
            ("rule.system_defined_alerts", "/",
             {"displayName": "Suspicious login", "state": "ACTIVE"})])
        findings = ts.check_alert_rules_off(self.ctx)
        self.assertEqual(["alert-rules-off"], self.finding_ids(findings))
        self.assertEqual(["User granted Admin privilege"],
                         [e["Alert"] for e in findings[0].evidence])

    def test_alert_rules_all_active_clean(self):
        self.write_policies([("rule.system_defined_alerts", "/",
                              {"displayName": "x", "state": "ACTIVE"})])
        self.assertEqual([], ts.check_alert_rules_off(self.ctx))

    def test_takeout_lists_enabled_services_only(self):
        self.write_policies([
            ("photos.user_takeout", "/", {"takeoutStatus": "ENABLED"}),
            ("maps.user_takeout", "/", {"takeoutStatus": "DISABLED"}),
            ("takeout.service_status", "/", {"serviceState": "ENABLED"})])
        findings = ts.check_takeout_services(self.ctx)
        self.assertEqual(["takeout-enabled"], self.finding_ids(findings))
        self.assertEqual({"photos", "takeout (master switch)"},
                         {e["Service"] for e in findings[0].evidence})

    def test_drive_for_desktop_unrestricted_vs_restricted(self):
        self.write_policies([("drive_and_docs.drive_for_desktop", "/",
                              {"allowDriveForDesktop": True,
                               "restrictToAuthorizedDevices": False})])
        self.assertEqual(["drive-desktop-any-device"], self.finding_ids(
            ts.check_drive_for_desktop(self.ctx)))
        self.write_policies([("drive_and_docs.drive_for_desktop", "/",
                              {"allowDriveForDesktop": True,
                               "restrictToAuthorizedDevices": True})])
        self.ctx._policy_cache = None
        self.assertEqual([], ts.check_drive_for_desktop(self.ctx))

    def test_meet_safety_dev_defaults_three_rows(self):
        self.write_policies([
            ("meet.safety_access", "/", {"meetingsAllowedToJoin": "ALL"}),
            ("meet.safety_domain", "/", {"usersAllowedToJoin": "ALL"}),
            ("meet.safety_host_management", "/",
             {"enableHostManagement": False})])
        findings = ts.check_meet_safety(self.ctx)
        self.assertEqual(["meet-safety-open"], self.finding_ids(findings))
        self.assertEqual(3, findings[0].count)

    def test_mail_delegation_policy_on(self):
        self.write_policies([("gmail.mail_delegation", "/",
                              {"enableMailDelegation": True})])
        self.assertEqual(["mail-delegation-allowed"], self.finding_ids(
            ts.check_mail_delegation_policy(self.ctx)))

    def test_api_controls_reported_raw_not_judged(self):
        self.write_policies([("api_controls.unconfigured_third_party_apps",
                              "/", {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED"})])
        findings = ts.check_api_controls(self.ctx)
        self.assertEqual("INFO", findings[0].severity)
        self.assertEqual("ACCESS_LEVEL_UNSPECIFIED",
                         findings[0].evidence[0]["Access level (raw)"])

    def test_password_login_enforcement_and_expiry_flagged(self):
        # Dev tenant's resolved root values, apart from the 90-day expiry.
        self.write_policies([("security.password", "/",
                              {"minimumLength": 14, "allowedStrength": "STRONG",
                               "allowReuse": False,
                               "enforceRequirementsAtLogin": False,
                               "expirationDuration": "7776000s"})])
        problem = ts.check_password_policy(self.ctx)[0].evidence[0]["Problem"]
        self.assertIn("not checked against the policy at next sign-in", problem)
        self.assertIn("expire every 90 days", problem)

    def test_password_never_expires_is_clean(self):
        self.write_policies([("security.password", "/",
                              {"minimumLength": 14, "allowedStrength": "STRONG",
                               "allowReuse": False,
                               "enforceRequirementsAtLogin": True,
                               "expirationDuration": "0s"})])
        self.assertEqual([], ts.check_password_policy(self.ctx))

    def test_2sv_methods_all_flagged_other_values_not(self):
        self.write_policies([
            ("security.two_step_verification_enforcement_factor", "/",
             {"allowedSignInFactorSet": "ALL"}),
            ("security.two_step_verification_enforcement_factor", "/Admins",
             {"allowedSignInFactorSet": "PASSKEY_ONLY"})])
        findings = ts.check_2sv_methods(self.ctx)
        self.assertEqual(["2sv-sms-allowed"], self.finding_ids(findings))
        self.assertEqual(["/"], [e["Org unit"] for e in findings[0].evidence])

    def test_shared_drive_controls_dev_defaults(self):
        self.write_policies([("drive_and_docs.shared_drive_creation", "/",
                              {"allowSharedDriveCreation": True,
                               "allowManagersToOverrideSettings": True,
                               "allowedPartiesForDownloadPrintCopy": "ALL"})])
        findings = ts.check_shared_drive_controls(self.ctx)
        self.assertEqual(["sd-controls-open"], self.finding_ids(findings))
        self.assertEqual(3, findings[0].count)

    def test_shared_drive_controls_locked_clean(self):
        self.write_policies([("drive_and_docs.shared_drive_creation", "/",
                              {"allowSharedDriveCreation": False,
                               "allowManagersToOverrideSettings": False,
                               "allowedPartiesForDownloadPrintCopy":
                                   "EDITORS_ONLY"})])
        self.assertEqual([], ts.check_shared_drive_controls(self.ctx))

    def test_meet_external_label_off_flagged(self):
        self.write_policies([("meet.safety_external_participants", "/",
                              {"enableExternalLabel": False})])
        findings = ts.check_meet_safety(self.ctx)
        self.assertEqual("External participants are not labelled",
                         findings[0].evidence[0]["Setting"])

    def test_raw_settings_table_lists_known_types_only(self):
        self.write_policies([
            ("security.passkeys_restriction", "/",
             {"allowedPasskeysType": "ANY_DEVICE_OR_PLATFORM"}),
            ("chat.chat_file_sharing", "/",
             {"externalFileSharing": "ALL_FILES"}),
            ("security.password", "/", {"minimumLength": 14})])
        findings = ts.check_policy_settings_raw(self.ctx)
        self.assertEqual(["policy-settings-raw"], self.finding_ids(findings))
        # Chat file sharing is judged by check_policy_baseline since
        # v1.7.0, so it is no longer repeated in the raw table.
        self.assertEqual({"Passkeys allowed"},
                         {e["Setting"] for e in findings[0].evidence})

    def test_console_only_list_emitted_with_policies(self):
        self.write_policies([("security.password", "/", {"minimumLength": 14})])
        findings = ts.check_console_only_settings(self.ctx)
        self.assertEqual(["console-only-settings"], self.finding_ids(findings))
        self.assertEqual(len(ts.CONSOLE_ONLY_SETTINGS), findings[0].count)


class TestLicenceWaste(CtxTestCase):
    DOMAININFO = ("Customer ID: C046t23xk\n"
                  "Primary Domain: dev.osh.co.za\n"
                  "Google Workspace Enterprise Plus Licenses: 50\n"
                  "Cloud Identity Licenses: 100\n"
                  "Users: 7\n")

    def write_domaininfo(self, text=None):
        (self.run_dir / "domaininfo.txt").write_text(
            text if text is not None else self.DOMAININFO, encoding="utf-8")

    def test_parse_owned_licences(self):
        owned = ts.parse_owned_licences(self.DOMAININFO)
        self.assertEqual(50, owned["Google Workspace Enterprise Plus"])
        self.assertEqual(100, owned["Cloud Identity"])

    def test_large_gap_flagged_and_free_cloud_identity_ignored(self):
        self.write_domaininfo()
        self.write_csv("licenses", """userId,productId,productDisplay,skuId,skuDisplay
a@example.com,Google-Apps,Google Workspace,1010020020,Google Workspace Enterprise Plus
b@example.com,101001,Cloud Identity,1010010001,Cloud Identity""")
        findings = ts.check_licence_waste(self.ctx)
        self.assertEqual(["licence-waste"], self.finding_ids(findings))
        self.assertEqual(1, len(findings[0].evidence))
        row = findings[0].evidence[0]
        self.assertEqual("50", row["Seats owned"])
        self.assertEqual("1", row["Assigned"])
        self.assertEqual("49", row["Unused"])

    def test_small_gap_clean(self):
        self.write_domaininfo("Business Starter Licenses: 10\n")
        self.write_csv("licenses", """userId,skuId,skuDisplay
a@example.com,1010020027,Business Starter
b@example.com,1010020027,Business Starter
c@example.com,1010020027,Business Starter
d@example.com,1010020027,Business Starter
e@example.com,1010020027,Business Starter
f@example.com,1010020027,Business Starter""")
        self.assertEqual([], ts.check_licence_waste(self.ctx))

    def test_no_domaininfo_no_finding(self):
        self.write_csv("licenses", """userId,skuId,skuDisplay
a@example.com,1010020020,Google Workspace Enterprise Plus""")
        self.assertEqual([], ts.check_licence_waste(self.ctx))

    def test_unparseable_domaininfo_yields_nothing(self):
        self.write_domaininfo("Customer ID: C1\nSome other line\n")
        self.assertEqual([], ts.check_licence_waste(self.ctx))


ADMINS_HEADER = ("roleAssignmentId,roleId,role,assignedTo,assignedToUser,"
                 "assignedToGroup,assignedToServiceAccount,assignedToUnknown,"
                 "scopeType,orgUnitId,orgUnit")


class TestAdminRoles(CtxTestCase):
    def test_suspended_holder_high_and_unresolved_medium(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-14T10:00:00Z,True,True,,True,False,Business
gone@example.com,True,False,2024-01-01T10:00:00Z,True,True,,False,True,Business""")
        self.write_csv("admins", f"""{ADMINS_HEADER}
1,r1,_SEED_ADMIN_ROLE,111,boss@example.com,,,False,CUSTOMER,,
2,r2,_USER_MANAGEMENT_ADMIN_ROLE,222,gone@example.com,,,False,CUSTOMER,,
3,r1,_SEED_ADMIN_ROLE,333,,,,True,CUSTOMER,,""")
        findings = ts.check_admin_roles(self.ctx)
        by_id = {f.fid: f for f in findings}
        self.assertIn("admin-role-suspended-holder", by_id)
        self.assertEqual("HIGH", by_id["admin-role-suspended-holder"].severity)
        self.assertEqual("gone@example.com",
                         by_id["admin-role-suspended-holder"]
                         .evidence[0]["User"])
        self.assertIn("admin-role-unresolved", by_id)
        self.assertEqual("333", by_id["admin-role-unresolved"]
                         .evidence[0]["Assigned to (ID)"])
        self.assertIn("admin-role-map", by_id)
        self.assertEqual(3, by_id["admin-role-map"].count)

    def test_sprawl_flagged_above_threshold(self):
        users = [f"u{i}@example.com,False,False,2026-08-14T10:00:00Z,"
                 "True,True,,False,False,Business" for i in range(10)]
        self.write_csv("users", USERS_HEADER + "\n" + "\n".join(users))
        admins = [f"{i},r1,ROLE,{i},u{i}@example.com,,,False,CUSTOMER,,"
                  for i in range(3)]
        self.write_csv("admins", ADMINS_HEADER + "\n" + "\n".join(admins))
        by_id = {f.fid: f for f in ts.check_admin_roles(self.ctx)}
        self.assertIn("admin-sprawl", by_id)
        self.assertEqual(3, by_id["admin-sprawl"].count)

    def test_small_tenant_sprawl_not_scored(self):
        # 3 admins of 7 users is normal for a small shop; the sprawl score
        # only applies from ADMIN_SPRAWL_MIN_USERS up.
        users = [f"u{i}@example.com,False,False,2026-08-14T10:00:00Z,"
                 "True,True,,False,False,Business" for i in range(7)]
        self.write_csv("users", USERS_HEADER + "\n" + "\n".join(users))
        admins = [f"{i},r1,ROLE,{i},u{i}@example.com,,,False,CUSTOMER,,"
                  for i in range(3)]
        self.write_csv("admins", ADMINS_HEADER + "\n" + "\n".join(admins))
        ids = self.finding_ids(ts.check_admin_roles(self.ctx))
        self.assertNotIn("admin-sprawl", ids)
        self.assertIn("admin-role-map", ids)

    def test_ou_scoped_role_shows_ou(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-14T10:00:00Z,True,True,,True,False,Business""")
        self.write_csv("admins", f"""{ADMINS_HEADER}
1,r1,HELPDESK,111,boss@example.com,,,False,ORG_UNIT,id:o1,/Sales""")
        by_id = {f.fid: f for f in ts.check_admin_roles(self.ctx)}
        self.assertEqual("OU /Sales",
                         by_id["admin-role-map"].evidence[0]["Scope"])


class TestMissingModules(CtxTestCase):
    def test_checks_skip_when_module_absent(self):
        # No CSVs at all: every check must return [] rather than raise, and
        # the missing modules land on the report's "not checked" list.
        for check in ts.CHECKS:
            if check is ts.check_console_only_settings:
                continue   # static hand-check list, true of every run
            self.assertEqual([], check(self.ctx),
                             f"{check.__name__} produced findings with no data")

    def test_console_only_list_needs_no_data(self):
        self.assertEqual(["console-only-settings"],
                         [f.fid for f in ts.check_console_only_settings(self.ctx)])

    def test_errored_module_not_usable(self):
        self.write_csv("forwards", """User,forwardEnabled,forwardTo
u@example.com,True,x@gmail.com""")
        self.ctx.set_module("forwards", "error", 0, "exit 2: boom")
        self.assertEqual([], ts.check_external_forwarding(self.ctx))


class TestPreflightParsing(unittest.TestCase):
    def test_parse_info_domain(self):
        out = ("Customer ID: C046t23xk\n"
               "Primary Domain: dev.osh.co.za\n"
               "Default Language: en\n")
        info = ts.parse_info_domain(out)
        self.assertEqual("dev.osh.co.za", info["primary_domain"])
        self.assertEqual("C046t23xk", info["customer_id"])

    def test_parse_serviceaccount_pass_and_fail(self):
        out = (
            "System time status\n"
            "        Service Account Private Key Authentication: PASS\n"
            "https://www.googleapis.com/auth/calendar, PASS (1/3)\n"
            "https://www.googleapis.com/auth/gmail.settings.basic, FAIL (2/3)\n"
            "https://www.googleapis.com/auth/drive, PASS (3/3)\n"
            "Some scopes FAILED!\n")
        passed, failed = ts.parse_serviceaccount_check(out)
        self.assertIn("https://www.googleapis.com/auth/calendar", passed)
        self.assertIn("https://www.googleapis.com/auth/gmail.settings.basic",
                      failed)
        self.assertNotIn("https://www.googleapis.com/auth/gmail.settings.basic",
                         passed)

    def test_header_only_detection(self):
        self.assertTrue(ts.is_header_only("Owner,id,name\n"))
        self.assertTrue(ts.is_header_only(""))
        self.assertFalse(ts.is_header_only("Owner,id\nme,1\n"))


class TestHelpers(unittest.TestCase):
    def test_col_is_case_insensitive(self):
        row = {"primaryEmail": "a@b.c", "isEnrolledIn2Sv": "True"}
        self.assertEqual("a@b.c", ts.col(row, "primaryemail"))
        self.assertEqual("True", ts.col(row, "isenrolledin2sv"))
        self.assertEqual("", ts.col(row, "missing"))

    def test_email_domain(self):
        self.assertEqual("example.com", ts.email_domain("A@Example.COM"))
        self.assertEqual("", ts.email_domain("not-an-email"))

    def test_external_pm_args_uses_notdomainlist(self):
        # `pm not domain "d1,d2"` matches every ACL (domain takes a single
        # regex); the recipe must use notdomainlist instead.
        args = ts.external_pm_args(["b.com", "a.com"])
        self.assertNotIn("not", args)
        self.assertEqual(2, args.count("notdomainlist"))
        self.assertIn("a.com,b.com", args)


class TestManifestResume(CtxTestCase):
    def test_manifest_roundtrip(self):
        self.ctx.set_module("users", "ok", 7)
        ctx2 = ts.RunContext(self.run_dir, make_args())
        self.assertEqual("ok", ctx2.module_status("users"))
        self.assertEqual(["example.com", "alias.example.com"],
                         ctx2.internal_domains)

    def test_internal_domains_persist(self):
        self.ctx.internal_domains = ["x.com"]
        self.ctx.save()
        ctx2 = ts.RunContext(self.run_dir, make_args())
        self.assertEqual(["x.com"], ctx2.internal_domains)

    def test_corrupt_manifest_starts_fresh(self):
        (self.run_dir / "manifest.json").write_text("{not json",
                                                    encoding="utf-8")
        ctx2 = ts.RunContext(self.run_dir, make_args())
        self.assertEqual("", ctx2.module_status("users"))


class TestModuleSelection(unittest.TestCase):
    def test_default_excludes_tier4(self):
        keys = {m["key"] for m in ts.selected_modules(make_args())}
        self.assertIn("users", keys)
        self.assertIn("dns", keys)
        # v1.7.0: filters run by default for the takeover-pattern check.
        self.assertIn("filters", keys)
        # Round 9: two full sweeps nothing reads moved out of the default.
        self.assertNotIn("gmailprofile", keys)
        self.assertNotIn("filecounts", keys)

    def test_full_includes_tier4(self):
        keys = {m["key"] for m in ts.selected_modules(make_args(full=True))}
        self.assertIn("vacation", keys)
        self.assertIn("caalevels", keys)

    def test_only(self):
        keys = {m["key"] for m in
                ts.selected_modules(make_args(only="users,groups"))}
        self.assertEqual({"users", "groups"}, keys)

    def test_skip_tier(self):
        keys = {m["key"] for m in
                ts.selected_modules(make_args(skip_tier=[2, 3]))}
        self.assertNotIn("sendas", keys)
        self.assertNotIn("mydrive_external", keys)
        self.assertIn("users", keys)

    def test_no_dns(self):
        keys = {m["key"] for m in ts.selected_modules(make_args(no_dns=True))}
        self.assertNotIn("dns", keys)


class TestDeriveInternalDomains(CtxTestCase):
    def test_domains_and_aliases_merge(self):
        self.write_csv("domains", """domainName,verified,type
example.com,True,primary
alias.example.com,True,alias""")
        self.write_csv("domainaliases", """domainAliasName,parentDomainName,verified
extra.example.com,example.com,True""")
        self.ctx.internal_domains = []
        ts.derive_internal_domains(self.ctx)
        self.assertEqual(["alias.example.com", "example.com",
                          "extra.example.com"],
                         self.ctx.internal_domains)


class TestBackupCodesRedaction(CtxTestCase):
    def test_live_codes_never_reach_disk(self):
        gam_output = ("User,verificationCodes,verificationCodesCount\n"
                      "a@example.com,12345678 87654321,8\n")
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: (0, gam_output, "")
        try:
            status, rows, note = ts.collect_backupcodes(
                self.ctx, ts.MODULE_BY_KEY["backupcodes"])
        finally:
            ts.run_gam = original
        self.assertEqual("ok", status)
        written = (self.run_dir / "backupcodes.csv").read_text(
            encoding="utf-8")
        self.assertNotIn("12345678", written)
        self.assertIn("verificationCodesCount", written)
        self.assertIn("8", written)


class TestCollectSimple(CtxTestCase):
    def test_exit_60_header_only_is_empty(self):
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: (60, "Owner,id,name\n", "no rows")
        try:
            status, rows, note = ts.collect_simple(
                self.ctx, ts.MODULE_BY_KEY["userinvitations"])
        finally:
            ts.run_gam = original
        self.assertEqual("empty", status)
        self.assertEqual(0, rows)

    def test_partial_output_is_kept(self):
        # `all users print X` exits 73 when one user has Gmail disabled but
        # still emits the other users' rows; those rows must not be lost.
        gam_output = ("User,forwardEnabled,forwardTo\n"
                      "a@example.com,False,\n"
                      "b@example.com,True,x@gmail.com\n")
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: (
            73, gam_output,
            "User: dead@example.com, Gmail Service/App not enabled (4/4)")
        try:
            status, rows, note = ts.collect_simple(
                self.ctx, ts.MODULE_BY_KEY["forwards"])
        finally:
            ts.run_gam = original
        self.assertEqual("ok", status)
        self.assertEqual(2, rows)
        self.assertIn("dead@example.com", note)
        written = (self.run_dir / "forwards.csv").read_text(encoding="utf-8")
        self.assertIn("b@example.com", written)
        # And a partial module still feeds the checks engine.
        self.ctx.set_module("forwards", status, rows, note)
        ids = [f.fid for f in ts.check_external_forwarding(self.ctx)]
        self.assertEqual(["external-forwarding"], ids)

    def test_header_only_with_user_skip_is_partial(self):
        # Nobody has forwarding set AND one user has Gmail disabled: GAM
        # emits a bare header and exits 73. Partial-empty, not an error.
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: (
            73, "User,forwardEnabled,forwardTo\n",
            "User: dead@example.com, Gmail Service/App not enabled (4/4)")
        try:
            status, rows, note = ts.collect_simple(
                self.ctx, ts.MODULE_BY_KEY["forwards"])
        finally:
            ts.run_gam = original
        self.assertEqual("empty", status)
        self.assertEqual(0, rows)
        self.assertTrue((self.run_dir / "forwards.csv").is_file())

    def test_browsers_forbidden_is_skipped(self):
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: (
            50, "", "ERROR: Chrome Browser Print Failed: Forbidden")
        try:
            status, rows, note = ts.collect_simple(
                self.ctx, ts.MODULE_BY_KEY["browsers"])
        finally:
            ts.run_gam = original
        self.assertEqual("skipped", status)
        self.assertIn("not authorised", note)

    def test_swm_external_filters_on_owner_domain(self):
        # The recipient of an externally-owned file sees no permissions
        # array, so pm filters can't decide externality — the collector
        # must keep/drop rows on owners.0.emailAddress in Python.
        self.write_csv("users", USERS_HEADER + "\n"
                       "u@example.com,False,False,2026-01-01T00:00:00Z,"
                       "True,True,r@x.com,False,False,Workspace")
        gam_output = (
            "Owner,id,name,owners,owners.0.emailAddress,sharedWithMeTime\n"
            "u@example.com,f1,ext.txt,1,paul@outside.co.za,2026-08-15T15:38:35Z\n"
            "u@example.com,f2,int.txt,1,other@example.com,2026-08-15T15:38:35Z\n")
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: (0, gam_output, "")
        try:
            status, rows, note = ts.collect_swm_external(
                self.ctx, ts.MODULE_BY_KEY["sharedwithme_external"])
        finally:
            ts.run_gam = original
        self.assertEqual("ok", status)
        self.assertEqual(1, rows)
        written = (self.run_dir /
                   "sharedwithme_external.csv").read_text(encoding="utf-8")
        self.assertIn("paul@outside.co.za", written)
        self.assertNotIn("other@example.com", written)

    def test_real_failure_is_error(self):
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: (2, "", "ERROR: something broke")
        try:
            status, rows, note = ts.collect_simple(
                self.ctx, ts.MODULE_BY_KEY["userinvitations"])
        finally:
            ts.run_gam = original
        self.assertEqual("error", status)
        self.assertIn("something broke", note)

    def test_caalevels_gcp_error_is_skipped_not_authorised(self):
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: (
            2, "", "Please grant service account the Access Context Manager "
                   "Editor role in your GCP organization.")
        try:
            status, rows, note = ts.collect_simple(
                self.ctx, ts.MODULE_BY_KEY["caalevels"])
        finally:
            ts.run_gam = original
        self.assertEqual("skipped", status)
        self.assertIn("not authorised", note)


class TestRender(CtxTestCase):
    def test_report_is_self_contained_and_lists_not_checked(self):
        self.ctx.manifest["meta"]["primary_domain"] = "example.com"
        self.ctx.manifest["preflight"] = [["GAM7 binary", "found", "-"]]
        self.ctx.set_module("sendas", "skipped", 0,
                            "not authorised: DWD scope missing")
        findings = [ts.Finding(
            "test", "CRITICAL", "Something <bad> & risky",
            "It means trouble.", "Fix it.",
            [{"User": "a@example.com"}], "users.csv")]
        out = ts.render_html(self.ctx, findings)
        html = out.read_text(encoding="utf-8")
        self.assertIn("Something &lt;bad&gt; &amp; risky", html)
        self.assertIn("Coverage gaps", html)
        self.assertIn("not authorised: DWD scope missing", html)
        # A partial module says what it DID cover, not just what failed.
        self.ctx.set_module("filters", "partial", 42, "some users failed")
        html = ts.render_html(self.ctx, findings).read_text(encoding="utf-8")
        self.assertIn("42 row(s) collected and checked (filters.csv)", html)
        # Self-contained: no external stylesheet/script/image references.
        self.assertNotIn("<script src", html)
        self.assertNotIn("<link", html)
        self.assertNotIn("<img", html)
        self.assertTrue((self.run_dir / "findings.csv").is_file())
        # The finding id is in the heading so a client can cite it.
        self.assertIn("<code class='fid'>test</code>", html)

    def test_evidence_csv_is_uncapped(self):
        rows = [{"User": f"u{i}@example.com"} for i in range(25)]
        findings = [ts.Finding("many", "MEDIUM", "t", "m", "r", rows,
                               "users.csv")]
        ts.render_html(self.ctx, findings)
        with open(self.run_dir / "findings_evidence.csv", newline="",
                  encoding="utf-8") as fh:
            out = list(_csv.DictReader(fh))
        self.assertEqual(25, len(out))
        self.assertEqual({"id": "many", "severity": "MEDIUM",
                          "evidence_id": "many:u24@example.com",
                          "change": "first_run",
                          "User": "u24@example.com"}, out[-1])
        self.assertEqual(ts.EVIDENCE_ROWS, len(findings[0].evidence))

    def test_checked_and_clean_lists_only_checks_that_saw_data(self):
        # Forwards collected and internal-only: clean. Users absent: the
        # super-admin check had nothing to read and must not claim clean.
        self.write_csv("forwards", """User,forwardEnabled,forwardTo
u@example.com,True,x@example.com""")
        ts.run_checks(self.ctx)
        titles = dict(self.ctx.clean_checks)
        self.assertIn(ts.CHECK_TITLES["check_external_forwarding"], titles)
        self.assertEqual("forwards",
                         titles[ts.CHECK_TITLES["check_external_forwarding"]])
        self.assertNotIn(ts.CHECK_TITLES["check_super_admin_count"], titles)
        html = ts.render_html(self.ctx, []).read_text(encoding="utf-8")
        self.assertIn("Checked and clean", html)
        self.assertIn(ts.CHECK_TITLES["check_external_forwarding"], html)

    ADMIN_ROW = ("boss@example.com,False,False,2026-08-01T10:00:00Z,True,"
                 "True,,True,False,Business")

    def test_clean_needs_every_module_the_check_read(self):
        # users collected, asps failed: no app password data exists, so the
        # admin app password check must not claim clean (bug in v1.6.2).
        self.write_csv("users", f"{USERS_HEADER}\n{self.ADMIN_ROW}")
        self.ctx.set_module("asps", "error", 0, "missing scope")
        ts.run_checks(self.ctx)
        titles = dict(self.ctx.clean_checks)
        self.assertNotIn(ts.CHECK_TITLES["check_admin_asps"], titles)
        # Control: with both collected and nothing found, it is clean.
        self.write_csv("asps", """User,codeId,name,creationTime
user@example.com,1,Old mail app,2025-01-01T00:00:00Z""")
        ts.run_checks(self.ctx)
        titles = dict(self.ctx.clean_checks)
        self.assertEqual("asps, users",
                         titles[ts.CHECK_TITLES["check_admin_asps"]])

    def test_partial_module_is_not_clean(self):
        self.write_csv("forwards", """User,forwardEnabled,forwardTo
u@example.com,False,""", status="partial")
        ts.run_checks(self.ctx)
        self.assertNotIn(ts.CHECK_TITLES["check_external_forwarding"],
                         dict(self.ctx.clean_checks))

    def test_optional_module_does_not_block_clean(self):
        # Password strength reads users only to drop suspended accounts;
        # without it the check still saw every password rating.
        self.write_csv("report_users", """email,accounts:password_strength,accounts:password_length_compliance
u@example.com,STRONG,COMPLIANT""")
        self.ctx.set_module("users", "error", 0, "denied")
        ts.run_checks(self.ctx)
        self.assertIn(ts.CHECK_TITLES["check_user_password_strength"],
                      dict(self.ctx.clean_checks))

    def test_every_check_has_a_title(self):
        for check in ts.CHECKS:
            self.assertIn(check.__name__, ts.CHECK_TITLES)

    def test_findings_sorted_by_severity_in_run_checks(self):
        self.write_csv("users", f"""{USERS_HEADER}
boss@example.com,False,False,2026-08-01T10:00:00Z,False,False,,True,False,Business""")
        findings = ts.run_checks(self.ctx)
        severities = [f.severity for f in findings]
        self.assertEqual(severities,
                         sorted(severities,
                                key=ts.SEVERITY_ORDER.index))


class TestPostureScore(unittest.TestCase):
    def f(self, sev, fid="x"):
        return ts.Finding(fid, sev, "t", "m", "r", [], "s")

    def test_clean_tenant_scores_100(self):
        self.assertEqual(100, ts.posture_score([]))
        self.assertEqual(100, ts.posture_score([self.f("INFO")] * 20))

    def test_halves_every_70_points(self):
        # 2 critical (30) + 4 high (28) + 4 medium (12) = 70 points.
        findings = ([self.f("CRITICAL")] * 2 + [self.f("HIGH")] * 4
                    + [self.f("MEDIUM")] * 4)
        self.assertEqual(50, ts.posture_score(findings))
        self.assertEqual(25, ts.posture_score(findings * 2))

    def test_never_zero(self):
        self.assertEqual(1, ts.posture_score([self.f("CRITICAL")] * 500))

    def test_internal_check_errors_do_not_count(self):
        self.assertEqual(100, ts.posture_score(
            [self.f("CRITICAL", "check-error-check_x")]))


class TestCompareWithPrevious(unittest.TestCase):
    """Two run folders side by side, as --output-dir lays them out."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def make_run(self, name, customer="C01", complete=True, modules=None,
                 collected="2026-09-01 08:00"):
        run_dir = self.root / name
        run_dir.mkdir()
        ctx = ts.RunContext(run_dir, make_args())
        ctx.manifest["meta"].update(customer_id=customer, complete=complete,
                                    collected_at=collected)
        for key, status in (modules or {"users": "ok"}).items():
            ctx.set_module(key, status, 1)
        return ctx

    def finding(self, fid, users, sev="HIGH"):
        f = ts.Finding(fid, sev, f"title {fid}", "m", "Fix it. Then more.",
                       [{"User": u, "Last sign-in": "today"} for u in users],
                       "users.csv")
        f.modules = ["users"]
        return f

    def test_first_run(self):
        ctx = self.make_run("tenant_audit_20261001_000000")
        f = self.finding("a", ["x@example.com"])
        history = ts.compare_with_previous(ctx, [f], ts.find_previous_run(ctx))
        self.assertEqual("first_run", f.change)
        self.assertEqual("", history["previous"])
        html = ts.render_html(ctx, [f]).read_text(encoding="utf-8")
        self.assertIn("first audit", html)
        self.assertNotIn("What changed since", html)

    def test_new_persisting_resolved_by_evidence_row(self):
        prev = self.make_run("tenant_audit_20260901_000000")
        ts.render_html(prev, [self.finding("a", ["x@example.com",
                                                 "y@example.com"]),
                              self.finding("gone", ["z@example.com"])])
        ctx = self.make_run("tenant_audit_20261001_000000",
                            collected="2026-10-01 08:00")
        a = self.finding("a", ["y@example.com", "w@example.com"])
        b = self.finding("b", ["q@example.com"], sev="CRITICAL")
        self.assertEqual(prev.run_dir.resolve(),
                         ts.find_previous_run(ctx).resolve())
        history = ts.compare_with_previous(ctx, [a, b],
                                           ts.find_previous_run(ctx))
        self.assertEqual("persisting", a.change)
        self.assertEqual("new", b.change)
        self.assertEqual(["gone"], [r["id"] for r in history["resolved"]])
        self.assertEqual("new", a.row_changes["a:w@example.com"])
        self.assertEqual("persisting", a.row_changes["a:y@example.com"])
        self.assertEqual(1, history["resolved_rows"])     # x was fixed
        html = ts.render_html(ctx, [b, a]).read_text(encoding="utf-8")
        self.assertIn("What changed since 2026-09-01 08:00", html)
        self.assertIn("title gone", html)
        self.assertIn("new this month", html)
        self.assertIn("also last month", html)
        self.assertIn("up from 0", html)          # critical tile
        self.assertIn("down from 2", html)        # high tile: a, gone -> a
        self.assertIn("Top actions", html)
        self.assertIn("<li><strong>title b</strong>. Fix it.</li>", html)

    def test_compared_on_what_ran(self):
        # caalevels (tier 4) ran in neither run and courses is n/a in both:
        # left out. A finding that reads no module compares as it is. One
        # that a module failed in BOTH runs is still not compared.
        mods = {"users": "ok", "courses": "n/a", "tokens": "error"}
        prev = self.make_run("tenant_audit_20260901_000000", modules=mods)
        old = [self.finding(fid, ["z@example.com"])
               for fid in ("edition", "byhand", "gone", "tok")]
        old[0].modules = ["caalevels", "users", "courses"]
        old[1].modules = []
        old[3].modules = ["tokens"]
        ts.render_html(prev, old)
        ctx = self.make_run("tenant_audit_20261001_000000", modules=mods)
        now = [self.finding(fid, ["z@example.com"])
               for fid in ("edition", "byhand", "tok")]
        now[0].modules = ["caalevels", "users", "courses"]
        now[1].modules = []
        now[2].modules = ["tokens"]
        history = ts.compare_with_previous(ctx, now,
                                           ts.find_previous_run(ctx))
        self.assertEqual(["persisting", "persisting", "not_compared"],
                         [f.change for f in now])
        self.assertEqual(["gone"], [r["id"] for r in history["resolved"]])

    def test_pre_170_run_cannot_resolve(self):
        prev = self.make_run("tenant_audit_20260901_000000")
        (prev.run_dir / "findings.csv").write_text(
            "severity,id,title,count\nHIGH,gone,t,1\n", encoding="utf-8")
        ctx = self.make_run("tenant_audit_20261001_000000")
        history = ts.compare_with_previous(ctx, [],
                                           ts.find_previous_run(ctx))
        self.assertEqual([], history["resolved"])
        self.assertEqual(["gone"], [r["id"] for r in history["not_compared"]])

    def test_partial_module_is_not_compared(self):
        prev = self.make_run("tenant_audit_20260901_000000")
        ts.render_html(prev, [self.finding("gone", ["z@example.com"])])
        ctx = self.make_run("tenant_audit_20261001_000000",
                            modules={"users": "partial"})
        a = self.finding("a", ["y@example.com"])
        history = ts.compare_with_previous(ctx, [a],
                                           ts.find_previous_run(ctx))
        self.assertEqual("not_compared", a.change)
        self.assertEqual([], history["resolved"])
        self.assertEqual(["gone"],
                         [r["id"] for r in history["not_compared"]
                          if isinstance(r, dict)])

    def test_module_missing_this_run_is_not_a_fix(self):
        # tokens collected last month, failed this month: an account that
        # dropped off a list built from it was not looked at, not fixed.
        prev = self.make_run("tenant_audit_20260901_000000",
                             modules={"users": "ok", "tokens": "ok"})
        old = self.finding("risk", ["x@example.com", "y@example.com"])
        old.modules = ["tokens", "users"]
        ts.render_html(prev, [old])
        ctx = self.make_run("tenant_audit_20261001_000000",
                            modules={"users": "ok", "tokens": "error"})
        now = self.finding("risk", ["y@example.com"])
        now.modules = ["tokens", "users"]
        history = ts.compare_with_previous(ctx, [now],
                                           ts.find_previous_run(ctx))
        self.assertEqual("not_compared", now.change)
        self.assertEqual(0, history["resolved_rows"])
        html = ts.render_html(ctx, [now]).read_text(encoding="utf-8")
        self.assertIn("not like for like", html)

    def test_baseline_is_complete_run_of_same_customer_only(self):
        self.make_run("tenant_audit_20260801_000000")
        self.make_run("tenant_audit_20260901_000000", customer="C99")
        self.make_run("tenant_audit_20260915_000000", complete=False)
        self.make_run("tenant_audit_20261101_000000")   # later, not earlier
        ctx = self.make_run("tenant_audit_20261001_000000")
        self.assertEqual("tenant_audit_20260801_000000",
                         ts.find_previous_run(ctx).name)

    def test_compare_with_flag_wins(self):
        other = self.make_run("tenant_audit_20260101_000000", customer="C99")
        ctx = self.make_run("tenant_audit_20261001_000000")
        ctx.args.compare_with = other.run_dir
        self.assertEqual(other.run_dir, ts.find_previous_run(ctx))

    def test_score_trend_oldest_first_and_capped(self):
        for month in range(1, 9):
            run = self.make_run(f"tenant_audit_2026{month:02d}01_000000",
                                collected=f"2026-{month:02d}-01 08:00")
            run.manifest["meta"]["posture_score"] = month * 10
            run.save()
        ctx = self.make_run("tenant_audit_20261001_000000",
                            collected="2026-10-01 08:00")
        trend = ts.score_trend(ctx, 95)
        self.assertEqual(ts.SCORE_TREND_RUNS, len(trend))
        self.assertEqual(("2026-10-01", 95), trend[-1])
        self.assertEqual(("2026-04-01", 40), trend[0])


class TestDriveSharingLog(CtxTestCase):
    HEADER = ("name,actor.email,id.time,doc_id,doc_title,new_value,"
              "target_user,visibility")

    def test_each_event_type(self):
        self.write_csv("report_drive_sharing", f"""{self.HEADER}
change_document_visibility,a@example.com,2026-10-01T09:00:00Z,d1,Budget,people_with_link,,people_with_link
change_document_visibility,a@example.com,2026-10-01T09:01:00Z,d2,Plan,public_on_the_web,,public_on_the_web
change_document_visibility,a@example.com,2026-10-01T09:02:00Z,d3,Memo,public_in_the_domain,,public_in_the_domain
change_document_visibility,a@example.com,2026-10-01T09:03:00Z,d4,Old,private,,private
change_user_access,b@example.com,2026-10-02T09:00:00Z,d5,Deck,can_view,x@partner.example,shared_externally
change_user_access,b@example.com,2026-10-02T09:00:00Z,d5,Deck,can_view,x@partner.example,shared_externally
change_user_access,b@example.com,2026-10-02T09:01:00Z,d6,Sheet,can_edit,partner.example,shared_externally
change_user_access,c@example.com,2026-10-02T09:02:00Z,d7,Notes,can_edit,team@example.com,shared_internally
change_user_access,c@example.com,2026-10-02T09:03:00Z,d8,Notes,can_view,alias.example.com,shared_internally
change_user_access,c@example.com,2026-10-02T09:04:00Z,d9,Gone,none,y@partner.example,private""")
        found = {f.fid: f for f in ts.check_drive_sharing_log(self.ctx)}
        public = found["drive-made-public-30d"]
        self.assertEqual("HIGH", public.severity)
        self.assertEqual({"d1": "anyone with the link",
                          "d2": "public on the web"},
                         {r["File ID"]: r["Opened to"] for r in public.evidence})
        outside = found["drive-shared-outside-30d"]
        self.assertEqual("MEDIUM", outside.severity)
        # Internal shares and removed access are ignored; a repeated event
        # for the same file counts once.
        self.assertEqual([{"User": "b@example.com", "Files shared out": "2",
                           "Outside recipients":
                               "partner.example, x@partner.example"}],
                         outside.evidence)

    def test_internal_only_is_clean(self):
        self.write_csv("report_drive_sharing", f"""{self.HEADER}
change_user_access,c@example.com,2026-10-02T09:02:00Z,d7,Notes,can_edit,team@example.com,shared_internally""")
        self.assertEqual([], ts.check_drive_sharing_log(self.ctx))

    def test_module_is_default_tier_with_both_events(self):
        mod = ts.MODULE_BY_KEY["report_drive_sharing"]
        self.assertEqual(1, mod["tier"])
        self.assertIn("change_document_visibility,change_user_access",
                      mod["args"])


class TestDwdGrants(CtxTestCase):
    def test_broad_grant_is_medium_and_narrow_is_info(self):
        self.write_csv("report_admin", """name,API_CLIENT_NAME,API_SCOPES,actor.email,id.time
AUTHORIZE_API_CLIENT_ACCESS,1031,"https://mail.google.com/,https://www.googleapis.com/auth/calendar",a@example.com,2026-10-01T09:00:00Z
CHANGE_APPLICATION_SETTING,,,a@example.com,2026-10-01T09:00:00Z""")
        found = ts.check_dwd_grants(self.ctx)
        self.assertEqual("MEDIUM", found[0].severity)
        self.assertEqual("full Gmail access",
                         found[0].evidence[0]["Broad access"])
        self.write_csv("report_admin", """name,API_CLIENT_NAME,API_SCOPES,actor.email,id.time
AUTHORIZE_API_CLIENT_ACCESS,2042,https://www.googleapis.com/auth/calendar,a@example.com,2026-10-01T09:00:00Z""")
        self.assertEqual("INFO", ts.check_dwd_grants(self.ctx)[0].severity)

    def test_no_grants_is_clean(self):
        self.write_csv("report_admin", """name,API_CLIENT_NAME,API_SCOPES
CHANGE_APPLICATION_SETTING,,""")
        self.assertEqual([], ts.check_dwd_grants(self.ctx))


class TestCredit(CtxTestCase):
    def test_report_carries_credit_without_script(self):
        html = ts.render_html(self.ctx, []).read_text(encoding="utf-8")
        for element_id in ("osh-credit-head", "osh-credit-foot"):
            self.assertEqual(1, html.count(ts._credit_html(element_id)))
        self.assertIn("Made with the Google Workspace Security Audit by "
                      "Outsource House (OSH.co.za): <a href='https://github.com/"
                      "PaulOgier/GoogleWorkspaceScripts'>github.com/PaulOgier/"
                      "GoogleWorkspaceScripts</a>", html)
        self.assertNotIn("Prepared by", html)
        # Shared copies (TamingShare, mail previews) run no scripts.
        self.assertNotIn("<script", html)
        self.assertNotIn("<noscript>", html)
        self.assertIn("<body>", html)


class TestUpgradeOpportunities(CtxTestCase):
    def test_business_starter_lists_dlp(self):
        self.write_csv("licenses", """userEmail,skuId,skuDisplay
u@example.com,1010020027,Google Workspace Business Starter""")
        ups = {u["Protection"] for u in ts.upgrade_opportunities(self.ctx)}
        self.assertIn("Data loss prevention (DLP)", ups)
        self.assertIn("Advanced mobile management", ups)
        html = ts.render_html(self.ctx, []).read_text(encoding="utf-8")
        self.assertIn("Upgrade opportunities", html)

    def test_enterprise_plus_lists_none(self):
        self.write_csv("licenses", """userEmail,skuId,skuDisplay
u@example.com,1010020020,Google Workspace Enterprise Plus""")
        self.assertEqual([], ts.upgrade_opportunities(self.ctx))

    def test_no_licence_data_lists_none(self):
        self.ctx.set_module("licenses", "error", 0, "denied")
        self.assertEqual([], ts.upgrade_opportunities(self.ctx))

    def test_every_gated_feature_has_a_note(self):
        for feature, _ in ts.EDITION_FEATURES:
            self.assertIn(feature, ts.UPGRADE_NOTES)


class TestMonthlyService(CtxTestCase):
    def patch(self, name, value):
        original = getattr(ts, name)
        setattr(ts, name, value)
        self.addCleanup(setattr, ts, name, original)

    def test_wrong_customer_id_aborts_before_collecting(self):
        calls = []

        def fake_gam(args, **_):
            calls.append(args[0])
            if args == ["info", "domain"]:
                return 0, "Customer ID: C0other\nPrimary Domain: other.example\n", ""
            return 0, "GAM 7.48.22", ""
        self.patch("locate_gam", lambda: "/usr/bin/gam")
        self.patch("run_gam", fake_gam)
        self.patch("https_reachable", lambda host: True)
        self.ctx.args.tenant_entry = {"customer_id": "C0right"}
        self.assertFalse(ts.preflight(self.ctx, []))
        self.assertEqual(["version", "info"], calls)   # nothing after identity
        self.assertIn("NOT C0right", self.ctx.manifest["preflight"][-1][2])

    def stub_gam_for(self, customer_id):
        def fake_gam(args, **_):
            if args == ["info", "domain"]:
                return 0, (f"Customer ID: {customer_id}\n"
                           "Primary Domain: example.com\n"), ""
            return 0, "GAM 7.48.22", ""
        self.patch("locate_gam", lambda: "/usr/bin/gam")
        self.patch("run_gam", fake_gam)
        self.patch("https_reachable", lambda host: True)

    def test_resume_against_another_customer_is_refused(self):
        self.ctx.manifest["meta"]["customer_id"] = "C_OLD"
        self.ctx.manifest["meta"]["primary_domain"] = "old.example"
        self.ctx.save()
        self.stub_gam_for("C_NEW")
        self.assertFalse(ts.preflight(self.ctx, []))
        meta = ts.RunContext(self.run_dir, make_args()).manifest["meta"]
        self.assertEqual("C_OLD", meta["customer_id"])
        self.assertEqual("old.example", meta["primary_domain"])
        self.assertIn("NOT C_OLD", self.ctx.manifest["preflight"][-1][2])

    def test_resume_against_the_same_customer_passes(self):
        self.ctx.manifest["meta"]["customer_id"] = "C_OLD"
        self.stub_gam_for("C_OLD")
        self.assertTrue(ts.preflight(self.ctx, []))

    def test_check_that_raises_holds_the_report_and_exits_2(self):
        self.ctx.manifest["meta"]["complete"] = True
        self.assertEqual((True, []), ts.delivery_gate(self.ctx))

        def boom(ctx):
            raise ValueError("bad row")
        self.patch("CHECKS", [boom])
        self.patch("CHECK_TITLES", {"boom": "Boom"})
        findings = ts.run_checks(self.ctx)
        self.assertEqual(["check-error-boom"], [f.fid for f in findings])
        ok, reasons = ts.delivery_gate(self.ctx)
        self.assertFalse(ok)
        self.assertEqual(["checks did not run: boom"], reasons)
        self.assertEqual(2, ts.exit_code(self.ctx))
        # The next run starts clean.
        self.patch("CHECKS", [])
        ts.run_checks(self.ctx)
        self.assertEqual((True, []), ts.delivery_gate(self.ctx))
        self.assertEqual(0, ts.exit_code(self.ctx))

    def test_break_glass_admin_not_dormant_but_listed(self):
        self.write_csv("users", f"""{USERS_HEADER}
bg@example.com,False,False,Never,True,True,,True,False,Business
old@example.com,False,False,Never,True,True,,True,False,Business""")
        self.ctx.manifest["meta"]["break_glass"] = ["bg@example.com"]
        findings = ts.run_checks(self.ctx)
        dormant = [r["User"] for f in findings if f.fid == "dormant-admin"
                   for r in f.all_evidence]
        self.assertEqual(["old@example.com"], dormant)
        self.assertEqual(["bg@example.com"],
                         self.ctx.manifest["meta"]["break_glass_seen"])
        html = ts.render_html(self.ctx, findings).read_text(encoding="utf-8")
        self.assertIn("excluded from the dormancy checks as configured: "
                      "bg@example.com", html)

    def test_delivery_gate_and_exit_codes(self):
        self.ctx.manifest["meta"]["complete"] = True
        self.write_csv("users", f"{USERS_HEADER}\n"
                       "u@example.com,False,False,Never,True,True,,False,False,Business")
        self.ctx.set_module("courses", "n/a", 0, "no Education licence held")
        self.assertEqual((True, []), ts.delivery_gate(self.ctx))
        self.assertEqual(0, ts.exit_code(self.ctx))
        self.ctx.set_module("asps", "error", 0, "denied")
        ok, reasons = ts.delivery_gate(self.ctx)
        self.assertFalse(ok)
        self.assertIn("asps", reasons[0])
        self.assertEqual(2, ts.exit_code(self.ctx))

        self.ctx.manifest["meta"]["complete"] = False
        self.assertIn("the run did not finish",
                      ts.delivery_gate(self.ctx)[1])
        self.assertEqual(130, ts.exit_code(self.ctx))
        code, _ = ts.finish(self.ctx)
        self.assertEqual(130, code)
        qa = (self.run_dir / "qa_report.html").read_text(encoding="utf-8")
        self.assertIn("Hold for review", qa)


    def test_load_tenants_requires_customer_id(self):
        path = self.run_dir / "tenants.json"
        path.write_text('{"tenants": {"a": {"name": "A"}}}', encoding="utf-8")
        with self.assertRaises(ts.ConfigError):
            ts.load_tenants(path)
        path.write_text('{"tenants": {"a": {"customer_id": "C01", '
                        '"break_glass": ["BG@Example.com"], '
                        '"gamcfgdir": "~/gam/a"}}}', encoding="utf-8")
        a = ts.load_tenants(path)["a"]
        self.assertEqual(["bg@example.com"], a["break_glass"])
        self.assertTrue(a["enabled"])
        self.assertFalse(a["gamcfgdir"].startswith("~"))

    def test_all_returns_worst_code_and_keeps_going(self):
        path = self.run_dir / "tenants.json"
        path.write_text(json.dumps({"tenants": {
            k: {"customer_id": k, "gamcfgdir": f"/cfg/{k}"}
            for k in ("a", "b", "c", "d")}}), encoding="utf-8")
        codes = {"a": 0, "b": 2, "d": 2}
        seen = []

        def fake_run(args, tenant):
            seen.append((tenant["key"], os.environ.get("GAMCFGDIR")))
            if tenant["key"] == "c":
                raise RuntimeError("boom")
            return codes[tenant["key"]]
        self.patch("run_tenant", fake_run)
        self.patch("check_for_updates", lambda: None)
        before = os.environ.get("GAMCFGDIR")
        # c raises (counts as 1); 1 outranks 2 in EXIT_PRIORITY.
        self.assertEqual(1, ts.main(["--all", "--tenants", str(path)]))
        self.assertEqual(["a", "b", "c", "d"], [k for k, _ in seen])
        self.assertEqual(before, os.environ.get("GAMCFGDIR"))


class TestDohFallbackParsing(unittest.TestCase):
    def test_doh_fallback_shapes(self):
        answers = {
            ("example.com", "MX"): ["10 smtp.google.com."],
            ("example.com", "TXT"): ["v=spf1 include:_spf.google.com ~all"],
            ("google._domainkey.example.com", "TXT"): [],
            ("_dmarc.example.com", "TXT"): [],
        }
        original = ts.doh_query
        ts.doh_query = lambda name, rtype, timeout=10: answers.get(
            (name, rtype), [])
        try:
            result = ts.doh_fallback("example.com")
        finally:
            ts.doh_query = original
        self.assertTrue(result["checks"]["mx"]["present"])
        self.assertTrue(result["checks"]["spf"]["present"])
        self.assertFalse(result["checks"]["dkim"]["present"])
        self.assertFalse(result["checks"]["dmarc"]["present"])


class TestBatchedPartialCoverage(CtxTestCase):
    """A forked scan exits 0 even when a mailbox failed inside a child."""

    def run_collect(self, rc, out, err):
        mod = dict(key="imap", args=["print", "imap"])
        captured = {}
        original = ts.run_gam
        ts.run_gam = lambda args, **kw: (rc, out, err)
        try:
            captured = ts.collect_simple(self.ctx, mod)
        finally:
            ts.run_gam = original
        return captured

    def test_exit_zero_with_a_mailbox_without_gmail_is_complete(self):
        # An account with Gmail switched off has nothing to read: complete,
        # and the note names it (v1.7.0; it was partial every month).
        status, rows, note = self.run_collect(
            0, "User,enabled\na@example.com,True\n",
            "Getting IMAP for b@example.com\n"
            "User: b@example.com, Gmail Service/App not enabled\n")
        self.assertEqual("ok", status)
        self.assertEqual(1, rows)
        self.assertEqual(ts.NO_SERVICE_NOTE + "b@example.com", note)

    def test_exit_zero_with_a_failed_mailbox_is_partial(self):
        # Control: a real failure alongside it keeps the module partial.
        status, rows, note = self.run_collect(
            0, "User,enabled\na@example.com,True\n",
            "User: b@example.com, Gmail Service/App not enabled\n"
            "ERROR: User: c@example.com, Quota exceeded\n")
        self.assertEqual("partial", status)
        self.assertEqual(1, rows)

    def test_clean_exit_zero_is_still_ok(self):
        status, rows, note = self.run_collect(
            0, "User,enabled\na@example.com,True\n", "Getting IMAP settings\n")
        self.assertEqual("ok", status)
        self.assertEqual("", note)


class TestNoServiceOnly(unittest.TestCase):
    def test_only_service_off_lines(self):
        err = ("Getting all Filters\nGot 3 Filters\n"
               "User: A@example.com, Gmail Service/App not enabled (1/9)\n"
               "User: b@example.com, Drive Service/App not enabled\n"
               "User: gone@example.com, Does not exist\n")
        self.assertEqual(["a@example.com", "b@example.com", "gone@example.com"],
                         ts.no_service_only(err))

    def test_any_other_failure_is_none(self):
        for line in ("Timed out after 900s", "ERROR: 403 Forbidden",
                     "User: x@example.com, Print Failed: Not Authorized"):
            with self.subTest(line=line):
                self.assertIsNone(ts.no_service_only(
                    "User: b@example.com, Gmail Service/App not enabled\n"
                    + line))


class TestRowsCache(CtxTestCase):
    def test_rows_parsed_once_then_cached(self):
        self.write_csv("groups", "email,name\na@example.com,A")
        calls = []
        original = ts.read_csv_rows
        ts.read_csv_rows = lambda p: (calls.append(p.name), original(p))[1]
        try:
            self.ctx.rows("groups")
            self.ctx.rows("groups")
            self.assertEqual(["groups.csv"], calls)
            # re-collecting the module must drop the cached copy
            self.write_csv("groups", "email,name\nb@example.com,B\nc@example.com,C")
            self.assertEqual(2, len(self.ctx.rows("groups")))
        finally:
            ts.read_csv_rows = original


class TestRunGamStreaming(unittest.TestCase):
    """run_gam streams stderr and keeps partial stdout when a command is killed."""

    SCRIPT = ("import sys, time\n"
              "print('User,thing')\n"
              "for i in range(3):\n"
              "    print(f'row{i},x'); sys.stdout.flush()\n"
              "    print(f'Got {i} files...', file=sys.stderr, flush=True)\n"
              "if '--hang' in sys.argv:\n"
              "    time.sleep(30)\n")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.script = Path(self._tmp.name) / "fake_gam.py"
        self.script.write_text(self.SCRIPT, encoding="utf-8")
        self._gam = ts.GAM_PATH
        ts.GAM_PATH = sys.executable

    def tearDown(self):
        ts.GAM_PATH = self._gam
        self._tmp.cleanup()

    def test_stdout_and_stderr_both_captured(self):
        rc, out, err = ts.run_gam([str(self.script)], timeout=30)
        self.assertEqual(0, rc)
        self.assertEqual(4, len(out.strip().splitlines()))
        self.assertEqual(3, len(err.strip().splitlines()))

    def test_timeout_keeps_the_rows_already_collected(self):
        rc, out, err = ts.run_gam([str(self.script), "--hang"], timeout=0.5)
        self.assertEqual(-1, rc)
        self.assertEqual(4, len(out.strip().splitlines()))
        self.assertTrue(err.strip().splitlines()[-1].startswith("Timed out after"))


class TestUserScanArgs(CtxTestCase):
    SCAN_USERS = f"""{USERS_HEADER}
live@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Business
never@example.com,False,False,Never,True,True,,False,False,Business
gone@example.com,True,False,2026-08-01T10:00:00Z,True,True,,False,False,Business"""

    def setUp(self):
        super().setUp()
        self.write_csv("users", self.SCAN_USERS)
        self.mod = dict(key="sendas",
                        args=["all", "users", "print", "sendas", "compact"])

    def test_rewrites_to_csvfile_batch_with_redirect(self):
        args, out = ts.user_scan_args(self.ctx, self.mod)
        self.assertEqual(str(self.run_dir.resolve() / "sendas.csv"), str(out))
        self.assertEqual(["config", "auto_batch_min"], args[:2])
        self.assertIn("multiprocess", args)
        self.assertIn("num_threads", args)
        # the tail survives, and `all users` is gone
        self.assertEqual(["print", "sendas", "compact"], args[-3:])
        self.assertNotIn("all", args)
        listing = [a for a in args if a.endswith(":primaryEmail")][0]
        self.assertTrue(Path(listing.split(":primary")[0]).exists())

    def test_suspended_and_never_login_excluded_when_asked(self):
        self.ctx.args.skip_never_logged_in = True
        listing = ts.scan_user_list(self.ctx)
        emails = [r["primaryEmail"] for r in ts.read_csv_rows(listing)]
        self.assertEqual(["live@example.com"], emails)
        self.assertEqual(1, self.ctx.manifest["meta"]["skipped_never_logged_in"])

    def test_never_login_kept_by_default(self):
        listing = ts.scan_user_list(self.ctx)
        emails = [r["primaryEmail"] for r in ts.read_csv_rows(listing)]
        self.assertEqual(["live@example.com", "never@example.com"], emails)

    def test_falls_back_to_all_users_without_users_csv(self):
        (self.run_dir / "users.csv").unlink()
        self.ctx.set_module("users", "empty", 0)
        args, out = ts.user_scan_args(self.ctx, self.mod)
        self.assertEqual(self.mod["args"], args)
        self.assertIsNone(out)

    def test_backupcodes_keeps_threading_but_drops_the_redirect(self):
        """Live codes must never reach disk via GAM's own CSV writer."""
        mod = dict(key="backupcodes",
                   args=["all", "users", "print", "backupcodes"])
        stripped = ts.collect_backupcodes_args(self.ctx, mod)
        self.assertNotIn("redirect", stripped)
        self.assertNotIn("multiprocess", stripped)
        self.assertNotIn("num_threads", stripped)
        self.assertEqual("0", stripped[stripped.index("auto_batch_min") + 1])
        self.assertEqual(["print", "backupcodes"], stripped[-2:])
        self.assertTrue(any(a.endswith(":primaryEmail") for a in stripped))

    def test_backupcodes_never_forks(self):
        """No redirect means no merge, so a fork interleaves child headers
        into the data: 4 mailboxes came back as 7 rows (dev tenant, 2026-08-17).
        """
        mod = [m for m in ts.MODULES if m["key"] == "backupcodes"][0]
        with tempfile.TemporaryDirectory() as tmp:
            ctx = ts.RunContext(Path(tmp), make_args())
            (Path(tmp) / "users.csv").write_text(
                "primaryEmail,suspended,archived,lastLoginTime\n"
                "a@example.com,False,False,Never\n", encoding="utf-8")
            ctx.set_module("users", "ok", 1)
            args = ts.collect_backupcodes_args(ctx, mod)
        self.assertEqual("0", args[args.index("auto_batch_min") + 1])
        self.assertNotIn("redirect", args)

    def test_non_user_module_untouched(self):
        mod = dict(key="groups", args=["print", "groups"])
        args, out = ts.user_scan_args(self.ctx, mod)
        self.assertEqual(["print", "groups"], args)
        self.assertIsNone(out)


class TestModuleTimeout(CtxTestCase):
    def test_all_users_scan_scales_with_tenant_size(self):
        self.ctx.manifest["meta"]["user_count"] = 2000
        mod = dict(key="sendas", args=["all", "users", "print", "sendas"])
        self.assertEqual(20000, ts.module_timeout(self.ctx, mod, 900))

    def test_small_tenant_keeps_the_floor(self):
        self.ctx.manifest["meta"]["user_count"] = 37
        mod = dict(key="sendas", args=["all", "users", "print", "sendas"])
        self.assertEqual(900, ts.module_timeout(self.ctx, mod, 900))

    def test_non_per_user_module_is_untouched(self):
        self.ctx.manifest["meta"]["user_count"] = 2000
        mod = dict(key="groups", args=["print", "groups"], timeout=600)
        self.assertEqual(600, ts.module_timeout(self.ctx, mod, 900))


class TestOpenReport(unittest.TestCase):
    def setUp(self):
        self.opened = []
        self.original = ts.webbrowser.open
        ts.webbrowser.open = lambda url: self.opened.append(url) or True

    def tearDown(self):
        ts.webbrowser.open = self.original

    # An absolute path on the running platform: "/tmp/..." has no drive on
    # Windows, and as_uri() rejects it.
    REPORT = Path.cwd() / "x" / "audit_report.html"

    def test_opens_as_file_uri(self):
        args = argparse.Namespace(no_open=False)
        self.assertTrue(ts.open_report(self.REPORT, args))
        self.assertEqual([self.REPORT.as_uri()], self.opened)

    def test_no_open_flag_respected(self):
        args = argparse.Namespace(no_open=True)
        self.assertFalse(ts.open_report(self.REPORT, args))
        self.assertEqual([], self.opened)

    def test_relative_path_is_resolved(self):
        # The default output directory is relative, and as_uri() rejects a
        # relative path, so the report never opened on a default run.
        args = argparse.Namespace(no_open=False)
        rel = Path("tenant_audit_runs") / "run" / "audit_report.html"
        self.assertTrue(ts.open_report(rel, args))
        self.assertEqual([rel.resolve().as_uri()], self.opened)


LIC_HEADER = "userId,productId,productDisplay,skuId,skuDisplay"


class TestClassroom(PolicyTestCase):
    """Round 9: Classroom, gated on an Education SKU so a company never
    sees school settings."""
    CLASSROOM = [
        ("classroom.class_membership", "/",
         {"whichClassesCanUsersJoin": "CLASSES_IN_DOMAIN",
          "whoCanJoinClasses": "ANYONE_IN_DOMAIN"}),
        ("classroom.teacher_permissions", "/",
         {"whoCanCreateClasses": "ALL_PENDING_AND_VERIFIED_TEACHERS"}),
        ("classroom.guardian_access", "/", {"allowAccess": False}),
    ]

    def test_business_tenant_sees_nothing(self):
        self.write_csv("licenses", f"""{LIC_HEADER}
a@example.com,Google-Apps,Google Workspace,1010020028,Google Workspace Business Standard""")
        self.write_policies(self.CLASSROOM)
        self.assertEqual([], ts.check_classroom_settings(self.ctx))
        self.assertEqual([], ts.education_skus_held(self.ctx))
        # Not applicable is not clean: the gate must not consult a module.
        self.ctx.consulted = []
        ts.check_classroom_settings(self.ctx)
        self.assertEqual([], self.ctx.consulted)
        status, _, note = ts.collect_classroom(self.ctx, ts.MODULE_BY_KEY["courses"])
        self.assertEqual("n/a", status)
        self.assertIn("no Education licence", note)

    def test_pending_teachers_can_create_classes_is_medium(self):
        # Google's default: a user who says "I'm a teacher" at first sign-in
        # is a pending teacher and can create classes unverified.
        self.write_csv("licenses", f"""{LIC_HEADER}
a@example.com,101031,Google Workspace for Education,1010310008,Google Workspace for Education Plus""")
        self.write_policies(self.CLASSROOM)
        by_id = {f.fid: f for f in ts.check_classroom_settings(self.ctx)}
        self.assertEqual({"classroom-open", "classroom-settings"}, set(by_id))
        self.assertEqual(3, by_id["classroom-settings"].count)
        self.assertIn("Education Plus", by_id["classroom-settings"].title)
        # No groups.csv: the teacher count says so rather than printing 0.
        self.assertIn("not read", by_id["classroom-open"].evidence[0]["Setting"])

    def test_verified_teachers_only_is_info_only(self):
        self.write_csv("licenses", f"""{LIC_HEADER}
a@example.com,101031,Google Workspace for Education,1010070001,Google Workspace for Education Fundamentals""")
        self.write_policies([
            ("classroom.teacher_permissions", "/",
             {"whoCanCreateClasses": "VERIFIED_TEACHERS_ONLY"})])
        self.assertEqual(["classroom-settings"],
                         self.finding_ids(ts.check_classroom_settings(self.ctx)))

    def test_teacher_group_count_read_from_groups(self):
        self.write_csv("groups", """email,name,directMembersCount
classroom_teachers@example.com,Classroom Teachers,4""")
        self.assertEqual("4", ts._classroom_teachers_count(self.ctx))

    def test_anyone_can_join_or_create_is_medium(self):
        self.write_csv("licenses", f"""{LIC_HEADER}
a@example.com,101031,Google Workspace for Education,1010070001,Google Workspace for Education Fundamentals""")
        self.write_policies([
            ("classroom.class_membership", "/",
             {"whoCanJoinClasses": "ANYONE"}),
            ("classroom.teacher_permissions", "/Students",
             {"whoCanCreateClasses": "ANYONE_IN_DOMAIN"})])
        by_id = {f.fid: f for f in ts.check_classroom_settings(self.ctx)}
        self.assertEqual({"classroom-open", "classroom-settings"}, set(by_id))
        self.assertEqual(["/", "/Students"],
                         [r["Org unit"] for r in by_id["classroom-open"].evidence])

    def test_courses_counted_by_state(self):
        self.write_csv("courses", """id,name,ownerId,courseState
1,Maths,100,ACTIVE
2,History,100,ACTIVE
3,Old,101,ARCHIVED""")
        findings = ts.check_courses(self.ctx)
        self.assertEqual(["classroom-courses"], self.finding_ids(findings))
        self.assertEqual(3, findings[0].count)
        self.assertEqual({"ACTIVE": "2", "ARCHIVED": "1"},
                         {r["State"]: r["Courses"] for r in findings[0].evidence})

    def test_classroom_collectors_run_after_the_tenant_pool(self):
        # A non-simple collector is a heavy module, so licenses.csv exists
        # when the gate reads it.
        for key in ("courses", "course_participants", "classroominvitations",
                    "guardians"):
            self.assertEqual("classroom",
                             ts.MODULE_BY_KEY[key].get("collector"), key)

    def test_progress_lines_before_header_are_stripped(self):
        # print classroominvitations writes per-course progress to stdout
        # ahead of the header (live, 2026-10-01).
        path = self.run_dir / "classroominvitations.csv"
        path.write_text(
            "Course: A (1), Print 0 Classroom Invitations (1/2)\n"
            "Course: B (2), Print 1 Classroom Invitation (2/2)\n"
            f"{self.INVITES}\n2,B,inv,TEACHER,9,guest@otherschool.org\n",
            encoding="utf-8")
        status, rows, _ = ts._strip_to_header(path, "courseId,", "ok", 3, "")
        self.assertEqual(("ok", 1), (status, rows))
        self.write_csv("classroominvitations", path.read_text(encoding="utf-8"))
        findings = ts.check_classroom_outsiders(self.ctx)
        self.assertEqual("guest@otherschool.org", findings[0].evidence[0]["Member"])

    def test_output_without_header_is_an_error_not_zero(self):
        path = self.run_dir / "classroominvitations.csv"
        path.write_text("Course: A (1), Print 0 Classroom Invitations\n",
                        encoding="utf-8")
        status, rows, note = ts._strip_to_header(path, "courseId,", "ok", 1, "")
        self.assertEqual(("error", 0), (status, rows))
        self.assertIn("no CSV header", note)

    def test_every_classroom_module_declares_its_header(self):
        for mod in ts.MODULES:
            if mod.get("collector") == "classroom":
                self.assertTrue(mod.get("csv_header"), mod["key"])

    # Headers below are copied from a live Education tenant run, 2026-10-01.
    COURSES = "id,name,courseState,ownerEmail,ownerId"

    def test_orphaned_courses_deleted_and_suspended_owner(self):
        self.write_csv("users", f"""{USERS_HEADER}
gone@example.com,True,False,2026-01-01T10:00:00Z,True,True,,False,False,Edu
here@example.com,False,False,2026-08-01T10:00:00Z,True,True,,False,False,Edu""")
        self.write_csv("courses", f"""{self.COURSES}
1,Maths,ACTIVE,here@example.com,1
2,Leaver,ACTIVE,gone@example.com,2
3,Ghost,ARCHIVED,Unknown user,3""")
        by_id = {f.fid: f for f in ts.check_courses(self.ctx)}
        self.assertEqual("MEDIUM", by_id["classroom-orphaned-courses"].severity)
        self.assertEqual({"Leaver": "Owner suspended",
                          "Ghost": "Owner account deleted"},
                         {r["Course"]: r["Problem"] for r in
                          by_id["classroom-orphaned-courses"].evidence})

    def test_courses_without_owner_column_are_not_orphaned(self):
        # A courses.csv collected before owneremail was added has no owner
        # column; that must not read as every owner deleted.
        self.write_csv("courses", """id,name,ownerId,courseState
1,Maths,100,ACTIVE""")
        self.assertEqual(["classroom-courses"],
                         self.finding_ids(ts.check_courses(self.ctx)))

    PARTICIPANTS = ("courseId,courseName,userRole,userId,profile.emailAddress,"
                    "profile.id,profile.name.fullName")
    INVITES = "courseId,courseName,id,role,userId,userEmail"

    def test_outsiders_on_roster_and_invited(self):
        self.write_csv("course_participants", f"""{self.PARTICIPANTS}
1,Maths,TEACHER,10,t@example.com,10,Teacher
1,Maths,STUDENT,11,s@alias.example.com,11,Student
1,Maths,TEACHER,12,helper@gmail.com,12,Helper
1,Maths,STUDENT,13,,13,Hidden""")
        self.write_csv("classroominvitations", f"""{self.INVITES}
1,Maths,inv1,STUDENT,14,new@example.com
2,Science,inv2,TEACHER,15,guest@otherschool.org""")
        findings = ts.check_classroom_outsiders(self.ctx)
        self.assertEqual(["classroom-external-members"], self.finding_ids(findings))
        self.assertEqual("HIGH", findings[0].severity)
        self.assertEqual([("helper@gmail.com", "on the roster"),
                          ("guest@otherschool.org", "invited")],
                         [(r["Member"], r["Status"]) for r in findings[0].evidence])
        self.assertIn("1 roster or invitation row(s) carried no email",
                      findings[0].meaning)

    def test_all_internal_members_is_clean(self):
        self.write_csv("course_participants", f"""{self.PARTICIPANTS}
1,Maths,TEACHER,10,t@example.com,10,Teacher""")
        self.write_csv("classroominvitations", self.INVITES)
        self.assertEqual([], ts.check_classroom_outsiders(self.ctx))

    GUARDIANS = ("studentEmail,studentId,invitedEmailAddress,invitationId,"
                 "creationTime,state,guardianId,guardianProfile.emailAddress")

    def test_guardians_accepted_pending_and_stale(self):
        old = (ts.datetime.now(ts.timezone.utc) - ts.timedelta(days=45)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        new = (ts.datetime.now(ts.timezone.utc) - ts.timedelta(days=2)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        self.write_csv("guardians", f"""{self.GUARDIANS}
a@example.com,1,p1@home.net,i1,{old},PENDING,,
b@example.com,2,p1@home.net,i2,{new},PENDING,,
c@example.com,3,p2@home.net,,,,g1,p2@home.net""")
        findings = ts.check_classroom_guardians(self.ctx)
        self.assertEqual(["classroom-guardians"], self.finding_ids(findings))
        self.assertEqual("1 guardian(s) receive student summaries, "
                         "2 invitation(s) pending (1 older than 30 days)",
                         findings[0].title)
        self.assertEqual({"a@example.com": ("pending", "p1@home.net"),
                          "b@example.com": ("pending", "p1@home.net"),
                          "c@example.com": ("accepted", "p2@home.net")},
                         {r["Student"]: (r["Status"], r["Guardian"])
                          for r in findings[0].evidence})


class TestEditionFeatures(PolicyTestCase):
    def test_business_standard_is_silent(self):
        self.write_csv("licenses", f"""{LIC_HEADER}
a@example.com,Google-Apps,Google Workspace,1010020028,Google Workspace Business Standard""")
        self.assertEqual([], ts.check_edition_features(self.ctx))

    def test_archived_user_sku_grants_nothing(self):
        self.write_csv("licenses", f"""{LIC_HEADER}
a@example.com,101034,Archived,1010340001,Google Workspace Enterprise Plus - Archived User""")
        self.assertEqual([], ts.check_edition_features(self.ctx))

    def test_enterprise_plus_without_dlp_rules_flags_unused(self):
        self.write_csv("licenses", f"""{LIC_HEADER}
a@example.com,Google-Apps,Google Workspace,1010020020,Google Workspace Enterprise Plus""")
        self.write_policies([("security.password", "/", {"minimumLength": 14})])
        by_id = {f.fid: f for f in ts.check_edition_features(self.ctx)}
        self.assertEqual({"edition-security-unused",
                          "edition-security-features"}, set(by_id))
        self.assertEqual(["Data loss prevention (DLP)"],
                         [e["Feature"] for e in
                          by_id["edition-security-unused"].evidence])
        # All five gated features are included in Enterprise Plus.
        self.assertEqual(5, by_id["edition-security-features"].count)

    def test_active_dlp_rule_counts_as_in_use(self):
        self.write_csv("licenses", f"""{LIC_HEADER}
a@example.com,Google-Apps,Google Workspace,1010020020,Google Workspace Enterprise Plus""")
        self.write_policies([("rule.dlp", "/",
                              {"displayName": "[Default] Card", "state": "ACTIVE"})])
        ids = self.finding_ids(ts.check_edition_features(self.ctx))
        self.assertEqual(["edition-security-features"], ids)

    def test_business_plus_gets_only_mobile_management(self):
        self.write_csv("licenses", f"""{LIC_HEADER}
a@example.com,Google-Apps,Google Workspace,1010020025,Google Workspace Business Plus""")
        findings = ts.check_edition_features(self.ctx)
        self.assertEqual(["Advanced mobile management"],
                         [e["Feature"] for e in findings[0].evidence])


ADMIN_HEADER = ("name,NEW_VALUE,OLD_VALUE,ROLE_NAME,RULE_NAME,SETTING_NAME,"
                "USER_EMAIL,actor.email,id.time")
LOGIN_HEADER = "name,actor.email,id.time,ipAddress,networkInfo.regionCode"
ALERTS_HEADER = "alertId,createTime,type,source,metadata.severity,metadata.status"


class TestActivityChecks(CtxTestCase):
    def test_admin_settings_detailed_licence_churn_counted(self):
        self.write_csv("report_admin", f"""{ADMIN_HEADER}
CHANGE_APPLICATION_SETTING,false,true,,,Enforce 2SV,,boss@example.com,2026-09-10T10:00:00Z
USER_LICENSE_ASSIGNMENT,x,,,,,a@example.com,,2026-09-10T09:00:00Z
USER_LICENSE_ASSIGNMENT,x,,,,,b@example.com,,2026-09-10T09:00:00Z""")
        by_id = {f.fid: f for f in ts.check_admin_activity(self.ctx)}
        self.assertEqual({"admin-setting-changes", "admin-activity-summary"},
                         set(by_id))
        change = by_id["admin-setting-changes"].evidence[0]
        self.assertEqual("Enforce 2SV: true -> false", change["Change"])
        self.assertEqual(1, by_id["admin-setting-changes"].count)
        self.assertEqual("USER_LICENSE_ASSIGNMENT",
                         by_id["admin-activity-summary"].evidence[0]["Event"])

    def test_admin_log_empty_no_findings(self):
        self.write_csv("report_admin", ADMIN_HEADER)
        self.assertEqual([], ts.check_admin_activity(self.ctx))

    def test_login_risk_high_and_failures_counted(self):
        self.write_csv("report_login", f"""{LOGIN_HEADER}
account_disabled_password_leak,a@example.com,2026-09-01T00:00:00Z,1.2.3.4,ZA
login_failure,b@example.com,2026-09-01T00:00:00Z,1.2.3.4,ZA
login_failure,b@example.com,2026-09-02T00:00:00Z,1.2.3.4,ZA
login_success,c@example.com,2026-09-02T00:00:00Z,1.2.3.4,ZA""")
        by_id = {f.fid: f for f in ts.check_login_risk(self.ctx)}
        self.assertEqual("HIGH", by_id["login-risk-events"].severity)
        self.assertEqual(1, by_id["login-risk-events"].count)
        self.assertEqual("2", by_id["login-failures"].evidence[0]["Failed sign-ins"])

    def test_blocked_sensitive_action_is_its_own_medium(self):
        self.write_csv("report_login", (
            "name,actor.email,id.time,ipAddress,networkInfo.regionCode,"
            "sensitive_action_name,login_challenge_method\n"
            "risky_sensitive_action_blocked,a@example.com,"
            "2026-09-30T12:00:00Z,1.2.3.4,ZA,Periodic check in Google Ads,none"))
        by_id = {f.fid: f for f in ts.check_login_risk(self.ctx)}
        # Google refused the action: not a HIGH "suspicious login".
        self.assertNotIn("login-risk-events", by_id)
        blocked = by_id["login-blocked-actions"]
        self.assertEqual("MEDIUM", blocked.severity)
        self.assertEqual("Periodic check in Google Ads",
                         blocked.evidence[0]["Action"])
        self.assertEqual("none", blocked.evidence[0]["Challenge"])

    def test_login_success_only_is_clean(self):
        self.write_csv("report_login", f"""{LOGIN_HEADER}
login_success,c@example.com,2026-09-02T00:00:00Z,1.2.3.4,ZA""")
        self.assertEqual([], ts.check_login_risk(self.ctx))

    def test_high_alert_raises_to_medium_and_sorts_first(self):
        self.write_csv("alerts", f"""{ALERTS_HEADER}
1,2026-09-01T00:00:00Z,Suspicious login,Google identity,LOW,NOT_STARTED
2,2026-08-20T00:00:00Z,Admin password reset,Sensitive Admin Action,HIGH,NOT_STARTED""")
        findings = ts.check_security_alerts(self.ctx)
        self.assertEqual("MEDIUM", findings[0].severity)
        self.assertEqual("HIGH", findings[0].evidence[0]["Severity"])

    def test_low_alerts_only_info(self):
        self.write_csv("alerts", f"""{ALERTS_HEADER}
1,2026-09-01T00:00:00Z,Suspicious login,Google identity,LOW,NOT_STARTED""")
        self.assertEqual("INFO", ts.check_security_alerts(self.ctx)[0].severity)

    def test_modules_not_run_no_findings(self):
        for check in (ts.check_admin_activity, ts.check_login_risk,
                      ts.check_security_alerts, ts.check_edition_features):
            self.assertEqual([], check(self.ctx))

    def test_alerts_module_is_default_tier_with_time_filter(self):
        mod = next(m for m in ts.MODULES if m["key"] == "alerts")
        self.assertEqual(1, mod["tier"])
        self.assertIn("createTime >=", mod["args"][-1])

    def test_login_module_requests_every_event_the_check_reads(self):
        mod = next(m for m in ts.MODULES if m["key"] == "report_login")
        requested = set(mod["args"][mod["args"].index("events") + 1].split(","))
        self.assertEqual(set(ts.LOGIN_RISK_EVENTS + ts.LOGIN_BLOCKED_EVENTS
                             + ts.LOGIN_FAILURE_EVENTS),
                         requested)


class TestVersionsInStep(unittest.TestCase):
    """The update check compares the remote VERSION file against
    SCRIPT_VERSION, so a release that bumps one and not the other tells every
    older user they are current. v1.4.2 shipped exactly that way."""

    ROOT = Path(__file__).resolve().parent

    def test_version_file_matches_script_version(self):
        self.assertEqual(
            (self.ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            ts.SCRIPT_VERSION)

    def test_docstring_header_matches_script_version(self):
        header = re.search(r"^Version:\s+(\S+)$", ts.__doc__, re.M)
        self.assertIsNotNone(header, "no Version: line in the module docstring")
        self.assertEqual(header.group(1), ts.SCRIPT_VERSION)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestCsvDataRows(unittest.TestCase):
    def test_multiline_cell_counts_as_one_row(self):
        text = ('User,message\n'
                'a@example.com,"line one\nline two"\n'
                'b@example.com,plain\n')
        self.assertEqual(2, ts.csv_data_rows(text))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.csv"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(2, ts.csv_data_rows(path))
        self.assertEqual(0, ts.csv_data_rows("User,message\n"))
        self.assertEqual(0, ts.csv_data_rows(""))


class TestScanSelectionEmpty(CtxTestCase):
    """Filters that leave nobody must skip the module, never widen to
    `all users` (which scans every mailbox in the tenant)."""

    def setUp(self):
        super().setUp()
        self.write_csv("users", USERS_HEADER + "\n"
                       "never@example.com,False,False,Never,True,True,,"
                       "False,False,Business")
        self.ctx.args.skip_never_logged_in = True

    def test_collect_simple_skips(self):
        calls = []
        original = ts.run_gam
        ts.run_gam = lambda args, **kw: calls.append(args) or (0, "", "")
        try:
            status, rows, note = ts.collect_simple(
                self.ctx, ts.MODULE_BY_KEY["sendas"])
        finally:
            ts.run_gam = original
        self.assertEqual("skipped", status)
        self.assertEqual([], calls)

    def test_backupcodes_skips(self):
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: self.fail("gam must not run")
        try:
            status, _, _ = ts.collect_backupcodes(
                self.ctx, ts.MODULE_BY_KEY["backupcodes"])
        finally:
            ts.run_gam = original
        self.assertEqual("skipped", status)


class TestBatchedRedirectCounting(CtxTestCase):
    def setUp(self):
        super().setUp()
        self.write_csv("users", USERS_HEADER + "\n"
                       "u@example.com,False,False,2026-01-01T00:00:00Z,"
                       "True,True,,False,False,Business")

    def test_redirect_file_is_counted_in_place(self):
        mod = ts.MODULE_BY_KEY["vacation"]

        def fake(args, **kw):
            path = Path(args[args.index("redirect") + 2])
            path.write_text('User,message\nu@example.com,"a\nb"\n',
                            encoding="utf-8")
            return 0, "", "Getting vacation for u@example.com\n"
        original = ts.run_gam
        ts.run_gam = fake
        try:
            status, rows, note = ts.collect_simple(self.ctx, mod)
        finally:
            ts.run_gam = original
        self.assertEqual("ok", status)
        self.assertEqual(1, rows)

    def test_marker_inside_csv_data_is_not_a_skip(self):
        mod = ts.MODULE_BY_KEY["sendas"]

        def fake(args, **kw):
            path = Path(args[args.index("redirect") + 2])
            path.write_text("User,signature\n"
                            "u@example.com,Does not exist? Ask me.\n",
                            encoding="utf-8")
            return 0, "", ""
        original = ts.run_gam
        ts.run_gam = fake
        try:
            status, rows, note = ts.collect_simple(self.ctx, mod)
        finally:
            ts.run_gam = original
        self.assertEqual("ok", status)

    def test_backupcodes_partial_keeps_the_counts(self):
        mod = ts.MODULE_BY_KEY["backupcodes"]
        original = ts.run_gam
        ts.run_gam = lambda *a, **k: (
            73, "User,verificationCodesCount\nu@example.com,10\n",
            "User: dead@example.com, Gmail Service/App not enabled")
        try:
            status, rows, note = ts.collect_backupcodes(self.ctx, mod)
        finally:
            ts.run_gam = original
        self.assertEqual("ok", status)
        self.assertIn("dead@example.com", note)
        self.assertEqual(1, rows)
        written = (self.run_dir / "backupcodes.csv").read_text(encoding="utf-8")
        self.assertIn("u@example.com,10", written)


class TestTier3Batched(CtxTestCase):
    def setUp(self):
        super().setUp()
        self.write_csv("users", USERS_HEADER + "\n"
                       "u@example.com,False,False,2026-01-01T00:00:00Z,"
                       "True,True,,False,False,Business")

    def test_mydrive_scan_is_one_batched_filelist(self):
        calls = []

        def fake(args, **kw):
            calls.append(args)
            return 0, "", ""
        original = ts.run_gam
        ts.run_gam = fake
        try:
            ts.collect_mydrive_external(
                self.ctx, ts.MODULE_BY_KEY["mydrive_external"])
        finally:
            ts.run_gam = original
        self.assertEqual(1, len(calls))
        args = calls[0]
        self.assertIn("multiprocess", args)
        self.assertNotIn("all", args)
        self.assertEqual(["print", "filelist"],
                         args[args.index("print"):args.index("print") + 2])
        self.assertIn("notdomainlist", args)


class TestCollectDnsStatus(CtxTestCase):
    def test_all_checks_failed_is_an_error(self):
        original = ts._dns_domain
        ts._dns_domain = lambda d, fb: {"path": "doh", "checks": {
            "mx": {"error": "x"}, "dmarc": {"error": "x"}}}
        try:
            status, rows, note = ts.collect_dns(
                self.ctx, ts.MODULE_BY_KEY["dns"])
        finally:
            ts._dns_domain = original
        self.assertEqual("error", status)

    def test_one_dead_domain_is_partial_and_order_is_kept(self):
        def fake(domain, fb):
            if domain == "alias.example.com":
                return {"path": "doh", "checks": {"mx": {"error": "x"}}}
            return {"path": "doh", "checks": {"mx": {"present": True}}}
        original = ts._dns_domain
        ts._dns_domain = fake
        try:
            status, rows, note = ts.collect_dns(
                self.ctx, ts.MODULE_BY_KEY["dns"])
        finally:
            ts._dns_domain = original
        self.assertEqual("partial", status)
        self.assertIn("alias.example.com", note)
        data = json.loads((self.run_dir / "dns.json").read_text(encoding="utf-8"))
        self.assertEqual(["example.com", "alias.example.com"], list(data))


class TestCollectOrdering(CtxTestCase):
    """domains/users first, then tenant-level prints together, then the
    per-mailbox scans one at a time - and a resumed partial is not re-run."""

    def test_order_and_manifest(self):
        seen = []

        def fake(args, **kw):
            key = "users" if "users" in args[:3] else args[-1]
            seen.append(key)
            if "users" in args[:3] and "print" in args:
                return (0, USERS_HEADER + "\nu@example.com,False,False,"
                        "2026-01-01T00:00:00Z,True,True,,False,False,Business\n",
                        "")
            if "domains" in args:
                return 0, "domainName,verified\nexample.com,True\n", ""
            return 0, "", ""
        mods = [ts.MODULE_BY_KEY[k] for k in
                ("sendas", "orgs", "users", "domains", "admins")]
        self.ctx.set_module("sendas", "partial", 3, "some users failed")
        original = ts.run_gam
        ts.run_gam = fake
        try:
            ts.collect(self.ctx, mods)
        finally:
            ts.run_gam = original
        self.assertEqual({"domains", "users"}, set(seen[:2]))
        self.assertNotIn("sendas", seen)          # partial, not timed out
        self.assertEqual("ok", self.ctx.module_status("users"))
        self.assertEqual("empty", self.ctx.module_status("orgs"))
        self.assertEqual("empty", self.ctx.module_status("admins"))
        self.assertEqual(1, self.ctx.manifest["meta"]["user_count"])
        self.assertIn("collected_at", self.ctx.manifest["meta"])
        self.assertFalse(self.ctx.manifest["meta"]["include_suspended"])


class TestResumeUnscannedSharedDrives(CtxTestCase):
    """A resume re-runs a scan that left drives UNSCANNED; with nothing
    unscanned it stays done."""

    NOTE = ("2 drive(s) UNSCANNED (admin not a member; re-run with "
            "--grant-temp-access to cover them)")

    def test_rescan_only_with_unscanned_note(self):
        mod = ts.MODULE_BY_KEY["shareddrive_external"]
        self.ctx.set_module("shareddrive_external", "empty", 0, self.NOTE)
        self.assertTrue(ts._needs_run(self.ctx, mod))
        self.ctx.set_module("shareddrive_external", "ok", 5, "")
        self.assertFalse(ts._needs_run(self.ctx, mod))


class TestTempGrantFailure(CtxTestCase):
    """A refused temp grant is reported with GAM's reason, not as a drive
    the operator should re-run with --grant-temp-access."""

    def test_unlicensed_admin_note(self):
        self.write_csv("shareddrives", "id,name\nD1,Finance")
        self.write_csv("shareddriveacls", "id,permission.emailAddress\n"
                       "D1,someone@example.com")
        self.ctx.args.grant_temp_access = True
        reason = ("Add Failed: Cannot set the requested role for that user "
                  "as they lack the necessary license.")
        original = ts.run_gam
        ts.run_gam = lambda args, **kw: (50, "", "User: a, " + reason + "\n")
        try:
            status, rows, note = ts.collect_sd_external(
                self.ctx, ts.MODULE_BY_KEY["shareddrive_external"])
        finally:
            ts.run_gam = original
        self.assertEqual(("partial", 0), (status, rows))
        self.assertIn("lack the necessary license", note)
        self.assertNotIn("UNSCANNED", note)

    def test_partial_from_grant_failure_is_not_rerun_on_resume(self):
        mod = ts.MODULE_BY_KEY["shareddrive_external"]
        self.ctx.set_module("shareddrive_external", "partial", 0,
                            "1 drive(s) not scanned, temp grant failed: x")
        self.assertFalse(ts._needs_run(self.ctx, mod))


class TestSharedDriveScanAsMember(CtxTestCase):
    """A drive the admin is not in is listed as an active member, organizers
    first, with no grant; a failing member falls through to the next."""

    def setUp(self):
        super().setUp()
        self.write_csv("users", "primaryEmail,suspended\n"
                       "org@example.com,False\nwriter@example.com,False\n"
                       "gone@example.com,True")
        self.write_csv("shareddrives", "id,name\nD1,Finance")
        self.write_csv("shareddriveacls",
                       "id,permission.emailAddress,permission.role,permission.type\n"
                       "D1,writer@example.com,writer,user\n"
                       "D1,gone@example.com,organizer,user\n"
                       "D1,org@example.com,organizer,user\n"
                       "D1,team@example.com,organizer,group")
        self.calls = []

    LISTING = "id,name,hasAugmentedPermissions\nF1,a.doc,True\nF2,b.doc,False\n"

    def two_step(self, acl_out, listing=None):
        """Step 1 answers the listing, step 2 the ACLs."""
        def fake(args):
            if "id,name,mimeType,hasaugmentedpermissions" in args:
                return 0, listing or self.LISTING, ""
            return 0, acl_out, ""
        return fake

    def run_with(self, fake):
        original = ts.run_gam
        ts.run_gam = lambda args, **kw: (self.calls.append(args), fake(args))[1]
        try:
            return ts.collect_sd_external(
                self.ctx, ts.MODULE_BY_KEY["shareddrive_external"])
        finally:
            ts.run_gam = original

    def test_organizer_first_no_grant(self):
        out = "id,name,permission.type\nF1,a.doc,anyone\n"
        status, rows, note = self.run_with(self.two_step(out))
        self.assertEqual(("ok", 1, ""), (status, rows, note))
        self.assertEqual("org@example.com", self.calls[0][1])
        self.assertFalse(any("drivefileacl" in c for c in self.calls))
        self.assertEqual("org@example.com",
                         self.ctx.rows("shareddrive_external")[0]["shareddrive.scannedAs"])

    def test_failed_member_falls_through(self):
        def fake(args):
            if args[1] == "org@example.com":
                return 1, "", "Drive Service/App not enabled\n"
            return self.two_step("id,name\nF1,a.doc\n")(args)
        status, rows, _ = self.run_with(fake)
        self.assertEqual(["org@example.com", "writer@example.com",
                          "writer@example.com"],
                         [c[1] for c in self.calls])
        self.assertEqual(("ok", 1), (status, rows))

    def test_drive_off_exit_60_is_not_an_empty_drive(self):
        # Seen live on dev 2026-10-02: Drive switched off for the member's
        # OU gives exit 60 and a header-only CSV, like an empty drive.
        def fake(args):
            if args[1] == "org@example.com":
                return (60, "Owner,id,name\n",
                        "User: org@example.com, Drive Service/App not enabled\n")
            return self.two_step("id,name\nF1,a.doc\n")(args)
        status, rows, _ = self.run_with(fake)
        self.assertEqual("writer@example.com", self.calls[-1][1])
        self.assertEqual(("ok", 1), (status, rows))

    def test_acls_fetched_only_for_files_with_their_own_sharing(self):
        out = "id,name,permission.type\nF1,a.doc,anyone\n"
        self.run_with(self.two_step(out))
        step1, step2 = self.calls
        # Step 1 asks for no permissions, so GAM makes no per-file calls.
        self.assertFalse(any("basicpermissions" in a for a in step1))
        self.assertNotIn("pm", step1)
        i = step2.index("csvfile")
        id_file = Path(step2[i + 1].rsplit(":id", 1)[0])
        self.assertEqual(["F1"], [r["id"] for r in ts.read_csv_rows(id_file)])
        self.assertIn("norecursion", step2)
        self.assertIn("pm", step2)

    def test_flagged_folder_is_listed_with_its_contents(self):
        # Children of a folder shared outside inherit it and are not
        # flagged themselves (dev, 2026-10-07): the folder is expanded.
        listing = ("id,name,mimeType,hasAugmentedPermissions\n"
                   "FO,Shared,application/vnd.google-apps.folder,True\n"
                   "C1,child,application/vnd.google-apps.document,False\n"
                   "F1,a.doc,application/vnd.google-apps.document,True\n")
        acls = ("id,name,permission.id,permission.type\n"
                "F1,a.doc,p1,user\n")
        folder_acls = ("id,name,permission.id,permission.type\n"
                       "FO,Shared,p2,user\nC1,child,p2,user\n"
                       "F1,a.doc,p1,user\n")

        def fake(args):
            if "id,name,mimeType,hasaugmentedpermissions" in args:
                return 0, listing, ""
            return 0, folder_acls if "showparent" in args else acls, ""
        status, rows, _ = self.run_with(fake)
        steps = self.calls[1:]
        self.assertEqual([["norecursion"], ["showparent"]],
                         [[a for a in c if a in ("norecursion", "showparent")]
                          for c in steps])
        # F1 came back from both calls; it is kept once.
        self.assertEqual(["F1", "FO", "C1"],
                         [r["id"] for r in
                          self.ctx.rows("shareddrive_external")])
        self.assertEqual(("ok", 3), (status, rows))

    def test_drive_with_no_own_sharing_needs_one_call(self):
        listing = "id,name,hasAugmentedPermissions\nF2,b.doc,False\n"
        status, rows, _ = self.run_with(self.two_step("", listing))
        self.assertEqual(1, len(self.calls))
        self.assertEqual(("empty", 0), (status, rows))

    def two_drives(self, d2_member=False):
        """D1 has an organizer; D2 has no active member (no grant allowed)."""
        acls = ("id,permission.emailAddress,permission.role,permission.type\n"
                "D1,org@example.com,organizer,user")
        if d2_member:
            acls += "\nD2,org@example.com,organizer,user"
        self.write_csv("shareddrives", "id,name\nD1,Finance\nD2,Legal")
        self.write_csv("shareddriveacls", acls)
        status, rows, note = self.run_with(
            self.two_step("id,name\nF1,a.doc\n"))
        self.ctx.set_module("shareddrive_external", status, rows, note)
        return status, note

    def test_unscanned_drive_is_partial_and_holds_delivery(self):
        status, note = self.two_drives()
        self.assertEqual("partial", status)
        self.assertIn("UNSCANNED", note)
        self.ctx.manifest["meta"]["complete"] = True
        ok, reasons = ts.delivery_gate(self.ctx)
        self.assertFalse(ok)
        self.assertIn("shareddrive_external", reasons[0])
        self.assertEqual(2, ts.exit_code(self.ctx))

    def test_partial_with_unscanned_marker_is_rerun_not_stuck(self):
        self.two_drives()
        self.assertTrue(ts._needs_run(
            self.ctx, ts.MODULE_BY_KEY["shareddrive_external"]))

    def test_all_drives_scanned_stays_ok(self):
        self.assertEqual("ok", self.two_drives(d2_member=True)[0])

    def test_partial_is_not_checked_and_clean(self):
        self.two_drives()
        ts.run_checks(self.ctx)
        self.assertFalse(any("shareddrive_external" in mods
                             for _, mods in self.ctx.clean_checks))


class TestTempGrantCleanup(CtxTestCase):
    """The one write the audit makes must be reported when it is not undone."""

    def setUp(self):
        super().setUp()
        self.write_csv("users", "primaryEmail,suspended\nsomeone@example.com,False")
        self.write_csv("shareddrives", "id,name\nD1,Finance")
        self.write_csv("shareddriveacls",
                       "id,permission.emailAddress,permission.role,permission.type\n"
                       "D1,someone@example.com,organizer,user")
        self.ctx.args.grant_temp_access = True
        self.ctx.manifest["meta"]["complete"] = True

    def run_collector(self, remove_rc):
        def fake(args, **kw):
            if args[1] == "someone@example.com":
                return 1, "", "Drive Service/App not enabled\n"
            if "delete" in args:
                return remove_rc, "", "Delete Failed: boom\n" if remove_rc else ""
            return 0, "id,name,hasAugmentedPermissions\nF2,b.doc,False\n", ""
        original = ts.run_gam
        ts.run_gam = fake
        try:
            status, rows, note = ts.collect_sd_external(
                self.ctx, ts.MODULE_BY_KEY["shareddrive_external"])
        finally:
            ts.run_gam = original
        self.ctx.set_module("shareddrive_external", status, rows, note)
        return status, note

    def test_failed_removal_is_recorded_gated_and_exit_2(self):
        status, note = self.run_collector(remove_rc=1)
        self.assertEqual("empty", status)
        self.assertEqual([{"drive": "Finance", "id": "D1",
                           "admin": "admin@example.com"}],
                         self.ctx.manifest["meta"]["temp_grant_cleanup_failed"])
        self.assertIn("NOT removed from Finance (D1)", note)
        ok, reasons = ts.delivery_gate(self.ctx)
        self.assertFalse(ok)
        self.assertIn("Finance (D1) for admin@example.com", reasons[0])
        self.assertEqual(2, ts.exit_code(self.ctx))
        qa = ts.render_qa(self.ctx, {}, (ok, reasons)).read_text(encoding="utf-8")
        self.assertIn("Finance (D1) for admin@example.com", qa)

    def test_clean_removal_leaves_the_gate_open(self):
        self.run_collector(remove_rc=0)
        self.assertEqual([], self.ctx.manifest["meta"]["temp_grant_cleanup_failed"])
        self.assertEqual((True, []), ts.delivery_gate(self.ctx))
        self.assertEqual(0, ts.exit_code(self.ctx))

    def test_earlier_failure_clears_only_when_a_rerun_removes_the_grant(self):
        self.run_collector(remove_rc=1)
        self.run_collector(remove_rc=0)
        self.assertEqual([], self.ctx.manifest["meta"]["temp_grant_cleanup_failed"])


class TestLicenceWasteGating(CtxTestCase):
    def test_no_licenses_module_no_finding(self):
        (self.run_dir / "domaininfo.txt").write_text(
            "Google Workspace Enterprise Plus Licenses: 50\n", encoding="utf-8")
        self.assertEqual([], ts.check_licence_waste(self.ctx))

    def test_archived_user_sku_is_not_summed_into_the_parent(self):
        (self.run_dir / "domaininfo.txt").write_text(
            "Workspace Enterprise Plus Licenses: 10\n"
            "Workspace Enterprise Plus - Archived User Licenses: 10\n",
            encoding="utf-8")
        rows = ["userId,skuId,skuDisplay"]
        rows += [f"a{i}@example.com,1,Google Workspace Enterprise Plus"
                 for i in range(8)]
        rows += [f"b{i}@example.com,2,Google Workspace Enterprise Plus - "
                 "Archived User" for i in range(2)]
        self.write_csv("licenses", "\n".join(rows))
        findings = ts.check_licence_waste(self.ctx)
        # Enterprise Plus: 10 owned, 8 assigned - clean. Archived: 10 owned,
        # 2 assigned - flagged, and NOT as 10 assigned via the substring.
        self.assertEqual(1, len(findings))
        self.assertEqual("2", findings[0].evidence[0]["Assigned"])


class TestAtRiskAdminRecovery(CtxTestCase):
    def test_admin_without_recovery_email_is_not_scored_for_it(self):
        self.write_csv("users", USERS_HEADER + "\n"
                       "boss@example.com,False,False,2026-08-30T10:00:00Z,"
                       "True,True,,True,False,Business")
        # Admin role alone is one factor; "no recovery email" must not be
        # the second, or following check_admin_recovery's advice flags you.
        self.assertEqual([], ts.check_at_risk_accounts(self.ctx))


class TestAtRiskRecoveryFactor(CtxTestCase):
    TOKENS = ("user,clientId,displayText,scopes\n"
              "u@example.com,1,App,https://mail.google.com/\n")

    def test_missing_recovery_email_is_not_a_factor(self):
        self.write_csv("users", USERS_HEADER + "\n"
                       "u@example.com,False,False,2026-09-30T10:00:00Z,"
                       "True,True,,False,False,Business")
        self.write_csv("tokens", self.TOKENS)
        # Risky app alone is one factor; no recovery email must not be the
        # second, or a company-wide app grant flags the whole tenant.
        self.assertEqual([], ts.check_at_risk_accounts(self.ctx))

    def test_personal_recovery_email_still_counts(self):
        self.write_csv("users", USERS_HEADER + "\n"
                       "u@example.com,False,False,2026-09-30T10:00:00Z,"
                       "True,True,me@gmail.com,False,False,Business")
        self.write_csv("tokens", self.TOKENS)
        findings = ts.check_at_risk_accounts(self.ctx)
        self.assertEqual(1, len(findings))
        self.assertEqual("personal recovery email, app with full mail/Drive "
                         "access", findings[0].evidence[0]["Risk factors"])


class TestParseArgsGuards(unittest.TestCase):
    def assertRejects(self, argv):
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                ts.parse_args(argv)

    def test_render_only_needs_run_dir(self):
        self.assertRejects(["--render-only"])

    def test_grant_needs_admin(self):
        self.assertRejects(["--grant-temp-access"])

    def test_skip_tier_parsed(self):
        self.assertEqual([2, 3], ts.parse_args(["--skip-tier", "2,3"]).skip_tier)
        self.assertRejects(["--skip-tier", "three"])


class TestPlainLogFile(unittest.TestCase):
    def test_ansi_stripped_from_the_file(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as tmp, \
                contextlib.redirect_stdout(io.StringIO()):
            ts.setup_logging(Path(tmp))
            ts.logger.info("\x1b[1;92mgreen\x1b[0m")
            # The suite silences _emit, so log what print_error would.
            ts.logger.error("\x1b[91m[ERROR] [CRITICAL] once\x1b[0m")
            logging_text = (Path(tmp) / "tenant_scope.log").read_text(
                encoding="utf-8")
            ts.logger = None
            import logging
            logging.shutdown()
        self.assertIn("green", logging_text)
        self.assertNotIn("\x1b[", logging_text)
        self.assertIn(" [ERROR] [CRITICAL] once", logging_text)
        self.assertEqual(1, logging_text.count("[ERROR]"))
