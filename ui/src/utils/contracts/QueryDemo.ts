/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumberish,
  BytesLike,
  FunctionFragment,
  Result,
  Interface,
  AddressLike,
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedListener,
  TypedContractMethod,
} from "./common";

export type ParsedPerChainQueryResponseStruct = {
  chainId: BigNumberish;
  queryType: BigNumberish;
  request: BytesLike;
  response: BytesLike;
};

export type ParsedPerChainQueryResponseStructOutput = [
  chainId: bigint,
  queryType: bigint,
  request: string,
  response: string,
] & { chainId: bigint; queryType: bigint; request: string; response: string };

export type ParsedQueryResponseStruct = {
  version: BigNumberish;
  senderChainId: BigNumberish;
  nonce: BigNumberish;
  requestId: BytesLike;
  responses: ParsedPerChainQueryResponseStruct[];
};

export type ParsedQueryResponseStructOutput = [
  version: bigint,
  senderChainId: bigint,
  nonce: bigint,
  requestId: string,
  responses: ParsedPerChainQueryResponseStructOutput[],
] & {
  version: bigint;
  senderChainId: bigint;
  nonce: bigint;
  requestId: string;
  responses: ParsedPerChainQueryResponseStructOutput[];
};

export type EthCallDataStruct = {
  contractAddress: AddressLike;
  callData: BytesLike;
  result: BytesLike;
};

export type EthCallDataStructOutput = [
  contractAddress: string,
  callData: string,
  result: string,
] & { contractAddress: string; callData: string; result: string };

export type EthCallByTimestampQueryResponseStruct = {
  requestTargetBlockIdHint: BytesLike;
  requestFollowingBlockIdHint: BytesLike;
  requestTargetTimestamp: BigNumberish;
  targetBlockNum: BigNumberish;
  targetBlockTime: BigNumberish;
  followingBlockNum: BigNumberish;
  targetBlockHash: BytesLike;
  followingBlockHash: BytesLike;
  followingBlockTime: BigNumberish;
  result: EthCallDataStruct[];
};

export type EthCallByTimestampQueryResponseStructOutput = [
  requestTargetBlockIdHint: string,
  requestFollowingBlockIdHint: string,
  requestTargetTimestamp: bigint,
  targetBlockNum: bigint,
  targetBlockTime: bigint,
  followingBlockNum: bigint,
  targetBlockHash: string,
  followingBlockHash: string,
  followingBlockTime: bigint,
  result: EthCallDataStructOutput[],
] & {
  requestTargetBlockIdHint: string;
  requestFollowingBlockIdHint: string;
  requestTargetTimestamp: bigint;
  targetBlockNum: bigint;
  targetBlockTime: bigint;
  followingBlockNum: bigint;
  targetBlockHash: string;
  followingBlockHash: string;
  followingBlockTime: bigint;
  result: EthCallDataStructOutput[];
};

export type EthCallQueryResponseStruct = {
  requestBlockId: BytesLike;
  blockNum: BigNumberish;
  blockTime: BigNumberish;
  blockHash: BytesLike;
  result: EthCallDataStruct[];
};

export type EthCallQueryResponseStructOutput = [
  requestBlockId: string,
  blockNum: bigint,
  blockTime: bigint,
  blockHash: string,
  result: EthCallDataStructOutput[],
] & {
  requestBlockId: string;
  blockNum: bigint;
  blockTime: bigint;
  blockHash: string;
  result: EthCallDataStructOutput[];
};

export type EthCallWithFinalityQueryResponseStruct = {
  requestBlockId: BytesLike;
  requestFinality: BytesLike;
  blockNum: BigNumberish;
  blockTime: BigNumberish;
  blockHash: BytesLike;
  result: EthCallDataStruct[];
};

export type EthCallWithFinalityQueryResponseStructOutput = [
  requestBlockId: string,
  requestFinality: string,
  blockNum: bigint,
  blockTime: bigint,
  blockHash: string,
  result: EthCallDataStructOutput[],
] & {
  requestBlockId: string;
  requestFinality: string;
  blockNum: bigint;
  blockTime: bigint;
  blockHash: string;
  result: EthCallDataStructOutput[];
};

export type SolanaAccountResultStruct = {
  account: BytesLike;
  lamports: BigNumberish;
  rentEpoch: BigNumberish;
  executable: boolean;
  owner: BytesLike;
  data: BytesLike;
};

export type SolanaAccountResultStructOutput = [
  account: string,
  lamports: bigint,
  rentEpoch: bigint,
  executable: boolean,
  owner: string,
  data: string,
] & {
  account: string;
  lamports: bigint;
  rentEpoch: bigint;
  executable: boolean;
  owner: string;
  data: string;
};

export type SolanaAccountQueryResponseStruct = {
  requestCommitment: BytesLike;
  requestMinContextSlot: BigNumberish;
  requestDataSliceOffset: BigNumberish;
  requestDataSliceLength: BigNumberish;
  slotNumber: BigNumberish;
  blockTime: BigNumberish;
  blockHash: BytesLike;
  results: SolanaAccountResultStruct[];
};

export type SolanaAccountQueryResponseStructOutput = [
  requestCommitment: string,
  requestMinContextSlot: bigint,
  requestDataSliceOffset: bigint,
  requestDataSliceLength: bigint,
  slotNumber: bigint,
  blockTime: bigint,
  blockHash: string,
  results: SolanaAccountResultStructOutput[],
] & {
  requestCommitment: string;
  requestMinContextSlot: bigint;
  requestDataSliceOffset: bigint;
  requestDataSliceLength: bigint;
  slotNumber: bigint;
  blockTime: bigint;
  blockHash: string;
  results: SolanaAccountResultStructOutput[];
};

export type SolanaPdaResultStruct = {
  programId: BytesLike;
  seeds: BytesLike[];
  account: BytesLike;
  lamports: BigNumberish;
  rentEpoch: BigNumberish;
  executable: boolean;
  owner: BytesLike;
  data: BytesLike;
  bump: BigNumberish;
};

export type SolanaPdaResultStructOutput = [
  programId: string,
  seeds: string[],
  account: string,
  lamports: bigint,
  rentEpoch: bigint,
  executable: boolean,
  owner: string,
  data: string,
  bump: bigint,
] & {
  programId: string;
  seeds: string[];
  account: string;
  lamports: bigint;
  rentEpoch: bigint;
  executable: boolean;
  owner: string;
  data: string;
  bump: bigint;
};

export type SolanaPdaQueryResponseStruct = {
  requestCommitment: BytesLike;
  requestMinContextSlot: BigNumberish;
  requestDataSliceOffset: BigNumberish;
  requestDataSliceLength: BigNumberish;
  slotNumber: BigNumberish;
  blockTime: BigNumberish;
  blockHash: BytesLike;
  results: SolanaPdaResultStruct[];
};

export type SolanaPdaQueryResponseStructOutput = [
  requestCommitment: string,
  requestMinContextSlot: bigint,
  requestDataSliceOffset: bigint,
  requestDataSliceLength: bigint,
  slotNumber: bigint,
  blockTime: bigint,
  blockHash: string,
  results: SolanaPdaResultStructOutput[],
] & {
  requestCommitment: string;
  requestMinContextSlot: bigint;
  requestDataSliceOffset: bigint;
  requestDataSliceLength: bigint;
  slotNumber: bigint;
  blockTime: bigint;
  blockHash: string;
  results: SolanaPdaResultStructOutput[];
};

export declare namespace QueryDemo {
  export type ChainEntryStruct = {
    chainID: BigNumberish;
    contractAddress: AddressLike;
    counter: BigNumberish;
    blockNum: BigNumberish;
    blockTime: BigNumberish;
  };

  export type ChainEntryStructOutput = [
    chainID: bigint,
    contractAddress: string,
    counter: bigint,
    blockNum: bigint,
    blockTime: bigint,
  ] & {
    chainID: bigint;
    contractAddress: string;
    counter: bigint;
    blockNum: bigint;
    blockTime: bigint;
  };
}

export declare namespace IWormhole {
  export type SignatureStruct = {
    r: BytesLike;
    s: BytesLike;
    v: BigNumberish;
    guardianIndex: BigNumberish;
  };

  export type SignatureStructOutput = [
    r: string,
    s: string,
    v: bigint,
    guardianIndex: bigint,
  ] & { r: string; s: string; v: bigint; guardianIndex: bigint };
}

export interface QueryDemoInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "QT_ETH_CALL"
      | "QT_ETH_CALL_BY_TIMESTAMP"
      | "QT_ETH_CALL_WITH_FINALITY"
      | "QT_MAX"
      | "QT_SOL_ACCOUNT"
      | "QT_SOL_PDA"
      | "VERSION"
      | "getMyCounter"
      | "getResponseDigest"
      | "getResponseHash"
      | "getState"
      | "parseAndVerifyQueryResponse"
      | "parseEthCallByTimestampQueryResponse"
      | "parseEthCallQueryResponse"
      | "parseEthCallWithFinalityQueryResponse"
      | "parseSolanaAccountQueryResponse"
      | "parseSolanaPdaQueryResponse"
      | "responsePrefix"
      | "updateCounters"
      | "updateRegistration"
      | "validateBlockNum"
      | "validateBlockTime"
      | "validateChainId"
      | "validateEthCallData"
      | "validateMultipleEthCallData"
      | "verifyQueryResponseSignatures"
      | "wormhole",
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "QT_ETH_CALL",
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: "QT_ETH_CALL_BY_TIMESTAMP",
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: "QT_ETH_CALL_WITH_FINALITY",
    values?: undefined,
  ): string;
  encodeFunctionData(functionFragment: "QT_MAX", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "QT_SOL_ACCOUNT",
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: "QT_SOL_PDA",
    values?: undefined,
  ): string;
  encodeFunctionData(functionFragment: "VERSION", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "getMyCounter",
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: "getResponseDigest",
    values: [BytesLike],
  ): string;
  encodeFunctionData(
    functionFragment: "getResponseHash",
    values: [BytesLike],
  ): string;
  encodeFunctionData(functionFragment: "getState", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "parseAndVerifyQueryResponse",
    values: [BytesLike, IWormhole.SignatureStruct[]],
  ): string;
  encodeFunctionData(
    functionFragment: "parseEthCallByTimestampQueryResponse",
    values: [ParsedPerChainQueryResponseStruct],
  ): string;
  encodeFunctionData(
    functionFragment: "parseEthCallQueryResponse",
    values: [ParsedPerChainQueryResponseStruct],
  ): string;
  encodeFunctionData(
    functionFragment: "parseEthCallWithFinalityQueryResponse",
    values: [ParsedPerChainQueryResponseStruct],
  ): string;
  encodeFunctionData(
    functionFragment: "parseSolanaAccountQueryResponse",
    values: [ParsedPerChainQueryResponseStruct],
  ): string;
  encodeFunctionData(
    functionFragment: "parseSolanaPdaQueryResponse",
    values: [ParsedPerChainQueryResponseStruct],
  ): string;
  encodeFunctionData(
    functionFragment: "responsePrefix",
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: "updateCounters",
    values: [BytesLike, IWormhole.SignatureStruct[]],
  ): string;
  encodeFunctionData(
    functionFragment: "updateRegistration",
    values: [BigNumberish, AddressLike],
  ): string;
  encodeFunctionData(
    functionFragment: "validateBlockNum",
    values: [BigNumberish, BigNumberish],
  ): string;
  encodeFunctionData(
    functionFragment: "validateBlockTime",
    values: [BigNumberish, BigNumberish],
  ): string;
  encodeFunctionData(
    functionFragment: "validateChainId",
    values: [BigNumberish, BigNumberish[]],
  ): string;
  encodeFunctionData(
    functionFragment: "validateEthCallData",
    values: [EthCallDataStruct, AddressLike[], BytesLike[]],
  ): string;
  encodeFunctionData(
    functionFragment: "validateMultipleEthCallData",
    values: [EthCallDataStruct[], AddressLike[], BytesLike[]],
  ): string;
  encodeFunctionData(
    functionFragment: "verifyQueryResponseSignatures",
    values: [BytesLike, IWormhole.SignatureStruct[]],
  ): string;
  encodeFunctionData(functionFragment: "wormhole", values?: undefined): string;

  decodeFunctionResult(
    functionFragment: "QT_ETH_CALL",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "QT_ETH_CALL_BY_TIMESTAMP",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "QT_ETH_CALL_WITH_FINALITY",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(functionFragment: "QT_MAX", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "QT_SOL_ACCOUNT",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(functionFragment: "QT_SOL_PDA", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "VERSION", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "getMyCounter",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "getResponseDigest",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "getResponseHash",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(functionFragment: "getState", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "parseAndVerifyQueryResponse",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "parseEthCallByTimestampQueryResponse",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "parseEthCallQueryResponse",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "parseEthCallWithFinalityQueryResponse",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "parseSolanaAccountQueryResponse",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "parseSolanaPdaQueryResponse",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "responsePrefix",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "updateCounters",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "updateRegistration",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "validateBlockNum",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "validateBlockTime",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "validateChainId",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "validateEthCallData",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "validateMultipleEthCallData",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: "verifyQueryResponseSignatures",
    data: BytesLike,
  ): Result;
  decodeFunctionResult(functionFragment: "wormhole", data: BytesLike): Result;
}

export interface QueryDemo extends BaseContract {
  connect(runner?: ContractRunner | null): QueryDemo;
  waitForDeployment(): Promise<this>;

  interface: QueryDemoInterface;

  queryFilter<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined,
  ): Promise<Array<TypedEventLog<TCEvent>>>;
  queryFilter<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined,
  ): Promise<Array<TypedEventLog<TCEvent>>>;

  on<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>,
  ): Promise<this>;
  on<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>,
  ): Promise<this>;

  once<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>,
  ): Promise<this>;
  once<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>,
  ): Promise<this>;

  listeners<TCEvent extends TypedContractEvent>(
    event: TCEvent,
  ): Promise<Array<TypedListener<TCEvent>>>;
  listeners(eventName?: string): Promise<Array<Listener>>;
  removeAllListeners<TCEvent extends TypedContractEvent>(
    event?: TCEvent,
  ): Promise<this>;

  QT_ETH_CALL: TypedContractMethod<[], [bigint], "view">;

  QT_ETH_CALL_BY_TIMESTAMP: TypedContractMethod<[], [bigint], "view">;

  QT_ETH_CALL_WITH_FINALITY: TypedContractMethod<[], [bigint], "view">;

  QT_MAX: TypedContractMethod<[], [bigint], "view">;

  QT_SOL_ACCOUNT: TypedContractMethod<[], [bigint], "view">;

  QT_SOL_PDA: TypedContractMethod<[], [bigint], "view">;

  VERSION: TypedContractMethod<[], [bigint], "view">;

  getMyCounter: TypedContractMethod<[], [bigint], "view">;

  getResponseDigest: TypedContractMethod<
    [response: BytesLike],
    [string],
    "view"
  >;

  getResponseHash: TypedContractMethod<[response: BytesLike], [string], "view">;

  getState: TypedContractMethod<
    [],
    [QueryDemo.ChainEntryStructOutput[]],
    "view"
  >;

  parseAndVerifyQueryResponse: TypedContractMethod<
    [response: BytesLike, signatures: IWormhole.SignatureStruct[]],
    [ParsedQueryResponseStructOutput],
    "view"
  >;

  parseEthCallByTimestampQueryResponse: TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [EthCallByTimestampQueryResponseStructOutput],
    "view"
  >;

  parseEthCallQueryResponse: TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [EthCallQueryResponseStructOutput],
    "view"
  >;

  parseEthCallWithFinalityQueryResponse: TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [EthCallWithFinalityQueryResponseStructOutput],
    "view"
  >;

  parseSolanaAccountQueryResponse: TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [SolanaAccountQueryResponseStructOutput],
    "view"
  >;

  parseSolanaPdaQueryResponse: TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [SolanaPdaQueryResponseStructOutput],
    "view"
  >;

  responsePrefix: TypedContractMethod<[], [string], "view">;

  updateCounters: TypedContractMethod<
    [response: BytesLike, signatures: IWormhole.SignatureStruct[]],
    [void],
    "nonpayable"
  >;

  updateRegistration: TypedContractMethod<
    [_chainID: BigNumberish, _contractAddress: AddressLike],
    [void],
    "nonpayable"
  >;

  validateBlockNum: TypedContractMethod<
    [_blockNum: BigNumberish, _minBlockNum: BigNumberish],
    [void],
    "view"
  >;

  validateBlockTime: TypedContractMethod<
    [_blockTime: BigNumberish, _minBlockTime: BigNumberish],
    [void],
    "view"
  >;

  validateChainId: TypedContractMethod<
    [chainId: BigNumberish, _validChainIds: BigNumberish[]],
    [void],
    "view"
  >;

  validateEthCallData: TypedContractMethod<
    [
      r: EthCallDataStruct,
      _expectedContractAddresses: AddressLike[],
      _expectedFunctionSignatures: BytesLike[],
    ],
    [void],
    "view"
  >;

  validateMultipleEthCallData: TypedContractMethod<
    [
      r: EthCallDataStruct[],
      _expectedContractAddresses: AddressLike[],
      _expectedFunctionSignatures: BytesLike[],
    ],
    [void],
    "view"
  >;

  verifyQueryResponseSignatures: TypedContractMethod<
    [response: BytesLike, signatures: IWormhole.SignatureStruct[]],
    [void],
    "view"
  >;

  wormhole: TypedContractMethod<[], [string], "view">;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment,
  ): T;

  getFunction(
    nameOrSignature: "QT_ETH_CALL",
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "QT_ETH_CALL_BY_TIMESTAMP",
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "QT_ETH_CALL_WITH_FINALITY",
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "QT_MAX",
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "QT_SOL_ACCOUNT",
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "QT_SOL_PDA",
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "VERSION",
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "getMyCounter",
  ): TypedContractMethod<[], [bigint], "view">;
  getFunction(
    nameOrSignature: "getResponseDigest",
  ): TypedContractMethod<[response: BytesLike], [string], "view">;
  getFunction(
    nameOrSignature: "getResponseHash",
  ): TypedContractMethod<[response: BytesLike], [string], "view">;
  getFunction(
    nameOrSignature: "getState",
  ): TypedContractMethod<[], [QueryDemo.ChainEntryStructOutput[]], "view">;
  getFunction(
    nameOrSignature: "parseAndVerifyQueryResponse",
  ): TypedContractMethod<
    [response: BytesLike, signatures: IWormhole.SignatureStruct[]],
    [ParsedQueryResponseStructOutput],
    "view"
  >;
  getFunction(
    nameOrSignature: "parseEthCallByTimestampQueryResponse",
  ): TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [EthCallByTimestampQueryResponseStructOutput],
    "view"
  >;
  getFunction(
    nameOrSignature: "parseEthCallQueryResponse",
  ): TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [EthCallQueryResponseStructOutput],
    "view"
  >;
  getFunction(
    nameOrSignature: "parseEthCallWithFinalityQueryResponse",
  ): TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [EthCallWithFinalityQueryResponseStructOutput],
    "view"
  >;
  getFunction(
    nameOrSignature: "parseSolanaAccountQueryResponse",
  ): TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [SolanaAccountQueryResponseStructOutput],
    "view"
  >;
  getFunction(
    nameOrSignature: "parseSolanaPdaQueryResponse",
  ): TypedContractMethod<
    [pcr: ParsedPerChainQueryResponseStruct],
    [SolanaPdaQueryResponseStructOutput],
    "view"
  >;
  getFunction(
    nameOrSignature: "responsePrefix",
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "updateCounters",
  ): TypedContractMethod<
    [response: BytesLike, signatures: IWormhole.SignatureStruct[]],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "updateRegistration",
  ): TypedContractMethod<
    [_chainID: BigNumberish, _contractAddress: AddressLike],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "validateBlockNum",
  ): TypedContractMethod<
    [_blockNum: BigNumberish, _minBlockNum: BigNumberish],
    [void],
    "view"
  >;
  getFunction(
    nameOrSignature: "validateBlockTime",
  ): TypedContractMethod<
    [_blockTime: BigNumberish, _minBlockTime: BigNumberish],
    [void],
    "view"
  >;
  getFunction(
    nameOrSignature: "validateChainId",
  ): TypedContractMethod<
    [chainId: BigNumberish, _validChainIds: BigNumberish[]],
    [void],
    "view"
  >;
  getFunction(
    nameOrSignature: "validateEthCallData",
  ): TypedContractMethod<
    [
      r: EthCallDataStruct,
      _expectedContractAddresses: AddressLike[],
      _expectedFunctionSignatures: BytesLike[],
    ],
    [void],
    "view"
  >;
  getFunction(
    nameOrSignature: "validateMultipleEthCallData",
  ): TypedContractMethod<
    [
      r: EthCallDataStruct[],
      _expectedContractAddresses: AddressLike[],
      _expectedFunctionSignatures: BytesLike[],
    ],
    [void],
    "view"
  >;
  getFunction(
    nameOrSignature: "verifyQueryResponseSignatures",
  ): TypedContractMethod<
    [response: BytesLike, signatures: IWormhole.SignatureStruct[]],
    [void],
    "view"
  >;
  getFunction(
    nameOrSignature: "wormhole",
  ): TypedContractMethod<[], [string], "view">;

  filters: {};
}
