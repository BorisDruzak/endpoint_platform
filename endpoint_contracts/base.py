from pydantic import BaseModel, ConfigDict


class ContractModelV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
