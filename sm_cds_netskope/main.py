import datetime
from .utils.sm_module import search_query, validate_credentials

from netskope.integrations.cre.plugin_base import (
    PluginBase,
    ValidationResult,
    PushResult,
)
from netskope.integrations.cre.models import Record, RecordType
from netskope.integrations.cre.models import Action


PLUGIN_NAME = "URE StealthMole CDS"


class StealthMolePlugin(PluginBase):

    def fetch_records(self):
        access_key = self.configuration.get("access_key").strip()
        secret_key = self.configuration.get("secret_key").strip()
        query = self.configuration.get("search_query").strip()
        init_range = self.configuration.get("init_range")

        self.logger.info(
            f"{PLUGIN_NAME} Plugin: Starting Pulling data from Stealthmole Compromised dataset."
        )

        if self.last_run_at:
            start = self.last_run_at
        elif init_range > 0:
            start = datetime.datetime.now() - datetime.timedelta(days=init_range)

        try:
            res = search_query(
                access_key=access_key,
                secret_key=secret_key,
                query=query,
                start=int(start.timestamp()),
            )
            ip_addresses = {
                data["victim_ip"] for data in res["data"] if data["victim_ip"]
            }
            users = {data["user"] for data in res["data"] if data["user"]}

            record_list = []
            for ioc in ip_addresses + users:
                record_list.append(
                    Record(
                        uid=ioc,
                        type=RecordType.USER,
                        score=None,
                    )
                )
            self.logger.info(f"{PLUGIN_NAME} Plugin: Finished pulling data.")
            return record_list
        except Exception as e:
            err_msg = "Validation error, Unable to pull data from SteatlthMole API."
            self.logger.error(f"{PLUGIN_NAME} Plugin: {err_msg}. Exception: {e}")
            return ValidationResult(success=False, message=err_msg)

    def validate(self, configuration):
        access_key = configuration.get("access_key").strip()
        secret_key = configuration.get("secret_key").strip()
        init_range = configuration.get("init_range").strip()

        res = validate_credentials(access_key, secret_key)
        res_json = res.json()

        if res.status_code != 200:
            err_msg = res_json["detail"]
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        elif res_json["CDS"]["allowed"] <= 0:
            err_msg = "Your account has exceeded CDS query limit."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        elif not isinstance(init_range, int):
            err_msg = "Invalid initial range provided in the configuration parameters."
            self.logger.error(f"{PLUGIN_NAME}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def get_actions(self):
        """Get available actions."""
        return []

    def validate_action(self, action: Action):
        return ValidationResult(success=True, message="Validation successful.")

    def get_action_fields(self, action: Action):
        """Get fields required for an action."""
        return []
