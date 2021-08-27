/*
* Copyright 2018-2020 TON DEV SOLUTIONS LTD.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

#[derive(Debug, thiserror::Error)]
pub enum AbiError {

    #[error( "Invalid data: {}", msg)]
    InvalidData {
        msg: String
    },

    #[error( "Invalid name: {}", name)]
    InvalidName {
        name: String
    },

    #[error( "Invalid function id: {:X}", id)]
    InvalidFunctionId {
        id: u32
    },

    #[error( "Deserialization error {}: {}", msg, cursor)]
    DeserializationError {
        msg: &'static str,
        cursor: ton_types::SliceData
    },

    #[error( "Not implemented")]
    NotImplemented,

    #[error( "Wrong parameters count. Expected: {}, provided: {}", expected, provided)]
    WrongParametersCount {
        expected: usize,
        provided: usize
    },

    #[error( "Wrong parameter type")]
    WrongParameterType,

    #[error( "Wrong data format:\n{}", val)]
    WrongDataFormat {
        val: serde_json::Value
    },

    #[error( "Invalid parameter length:\n{}", val)]
    InvalidParameterLength {
        val: serde_json::Value
    },

    #[error( "Invalid parameter value:\n{}", val)]
    InvalidParameterValue {
        val: serde_json::Value
    },

    #[error( "Incomplete deserialization error: {}", cursor)]
    IncompleteDeserializationError {
        cursor: ton_types::SliceData
    },

    #[error( "Invalid input data: {}", msg)]
    InvalidInputData {
        msg: String
    },

    #[error("Invalid version: {}", .0)]
    InvalidVersion(String),

    #[error( "Wrong function ID: {:x}", id)]
    WrongId {
        id: u32
    },

    #[error( "IO error: {}", err)]
    Io { 
        err: std::io::Error
    },

    #[error( "Serde json error: {}", err)]
    SerdeError {
        err: serde_json::Error
    },

    #[error( "Try from int error: {}", err)]
    TryFromIntError {
        err: std::num::TryFromIntError
    },

    #[error( "Tuple description should contain non empty `components` field")]
    EmptyComponents,

    #[error( "Type description contains non empty `components` field but it is not a tuple")]
    UnusedComponents,
}

