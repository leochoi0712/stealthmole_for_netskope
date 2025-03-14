import json
import datetime
import traceback
from .utils.sm_module import search_query, validate_credentials
from .utils.constants import *
from netskope.integrations.crev2.plugin_base import (
    PluginBase,
    ValidationResult,
    Entity,
    EntityField,
    EntityFieldType,
)
from netskope.integrations.crev2.models import Action, ActionWithoutParams


class StealthMolePlugin(PluginBase):
    def __init__(
        self,
        name,
        *args,
        **kwargs,
    ):
        """Init method.

        Args:
            name (str): Configuration name.
        """
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version, self.module_name = (
            self._get_plugin_info()
        )
        self.log_prefix = f"{self.module_name} {self.plugin_name} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name, version and module from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = StealthMolePlugin.metadata
            plugin_name = metadata_json.get("name", PLUGIN_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            module_name = metadata_json.get("module", MODULE_NAME)
            return (plugin_name, plugin_version, module_name)
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLUGIN_NAME, MODULE_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return (PLUGIN_NAME, PLUGIN_VERSION, MODULE_NAME)

    def get_entities(self) -> list[Entity]:
        """Get available entities."""
        return [
            Entity(
                name="Users",
                fields=[
                    EntityField(
                        name="Email", type=EntityFieldType.STRING, required=True
                    ),
                    EntityField(
                        name="Password", type=EntityFieldType.STRING, required=True
                    ),
                    EntityField(
                        name="Leaked From", type=EntityFieldType.STRING, required=True
                    ),
                ],
            )
        ]

    def fetch_records(self, entity: str):
        """Fetches entity records from a third party API."""
        if entity == "Users":
            access_key = self.configuration.get("access_key", "").strip()
            secret_key = self.configuration.get("secret_key", "").strip()
            query = self.configuration.get("search_query").strip()
            init_range = self.configuration.get("init_range")

            self.logger.info(f"{self.log_prefix}: Fetching {entity} from the platform.")

            if self.last_run_at:
                start = self.last_run_at
            elif init_range > 0:
                start = datetime.datetime.now() - datetime.timedelta(days=init_range)
            resp = search_query(
                access_key=access_key,
                secret_key=secret_key,
                query=f"email:{query}",
                # start=int(start.timestamp()),
            )
            resp_json = json.loads(resp.content)
            data = resp_json.get("data", [])
            records = []
            for record in data:
                records.append(
                    {
                        "Email": record["user"],
                        "Password": record["password"],
                        "Leaked Host": record["host"],
                    }
                )
        self.logger.info(
            f"{self.log_prefix}: Successfully fetched {len(records)} {entity} {records} from the platform."
        )

        return records

    def update_records(self, entity: str, records: list[dict]):
        """Update entity records from a third party API."""
        return records

    def validate(self, configuration: dict) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): dict object having all the Plugin
            configuration parameters.
        Returns:
            ValidateResult: ValidateResult object with success
            flag and message.
        """
        # Validate credentials
        access_key = configuration.get("access_key", "").strip()
        secret_key = configuration.get("secret_key", "").strip()
        resp = validate_credentials(access_key, secret_key)
        resp_json = resp.json()

        if resp.status_code != 200:
            err_msg = resp_json["detail"]
            self.logger.error(f"{self.log_prefix}: {VALIDATION_ERROR} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        elif resp_json["CDS"]["allowed"] <= 0:
            err_msg = "Your account has exceeded CDS query limit."
            self.logger.error(f"{self.log_prefix}: {VALIDATION_ERROR} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        # Validate initial range
        init_range = configuration.get("init_range")
        if not isinstance(init_range, int):
            err_msg = "Invalid initial range provided in the configuration parameters."
            self.logger.error(f"{self.log_prefix}: {VALIDATION_ERROR} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation successful.")

    def get_actions(self):
        """Get available actions."""
        return [ActionWithoutParams(label="No action", value="generate")]

    def get_action_params(self, action: Action):
        """Get fields required for an action."""
        if action.value in ["generate"]:
            return []

    def validate_action(self, action: Action):
        """Validate Action Parameters."""
        action_params = action.parameters
        if action.value not in ["generate"]:
            err_msg = "Unsupported action provided."
            self.logger.error(f"{self.log_prefix}: {err_msg}")
            return ValidationResult(success=False, message=err_msg)
        if action.value in ["generate"]:
            return ValidationResult(success=True, message="Validation successful.")

    def execute_action(self, action: Action):
        """Execute action on the record."""

        action_label = action.label
        action_params = action.parameters
        if action.value == "generate":
            self.logger.debug(
                f'{self.log_prefix}: Successfully executed "{action_label}" action.'
                " Note: No processing will be done from plugin for "
                f'the "{action_label}" action.'
            )
            return
