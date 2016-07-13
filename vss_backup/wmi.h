
// Odzhan

#ifndef WMI_H
#define WMI_H

#define _WIN32_DCOM
#define UNICODE 

#ifdef DEBUG
#define dprintf wprintf
#else
#define dprintf
#endif

#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>

#include <comdef.h>
#include <Wbemidl.h>
#include <wincred.h>

#ifndef WBEM_E_TRANSACTION_CONFLICT
#define WBEM_E_TRANSACTION_CONFLICT 0x8004106D
#endif

#ifndef WBEM_S_NEW_STYLE
#define WBEM_S_NEW_STYLE 0x400FF
#endif

#ifndef WBEM_E_FORCED_ROLLBACK
#define WBEM_E_FORCED_ROLLBACK 0x8004106E
#endif

typedef struct _VOLUME_INFO {
  std::wstring driveLetter;
  std::wstring driveType;
  std::wstring capacity;
  std::wstring freeSpace;
  std::wstring label;
} VOLUME_INFO, *PVOLUME_INFO;

//typedef struct _

typedef struct _WMI_ERROR {
  HRESULT hr;
  const PWCHAR wstrError;
} WMI_ERROR, *PWMI_ERROR;

class WMI {
  private:
    HRESULT hr;
    DWORD dwError;
    
    IWbemContext  *pContext;
    IWbemLocator  *pLocator;
    IWbemServices *pServices;
    std::wstring remote, machine, domain, username, password;
    std::wstring shadowID, shadowObj;
    
    BOOL SetBlanket(IUnknown *);
    DWORD ExecCommand(std::wstring, BOOL, BOOL);
    VOID WaitOnProcess(std::wstring);
    
    VOID GetDeviceObject(VOID);
    BOOL CreateShadow(std::wstring);
    VOID CopyFolder(std::wstring, std::wstring, std::wstring);
    
    COAUTHIDENTITY auth, *pAuth;
  public:
    WMI();
    ~WMI();
    
    BOOL Open(std::wstring, std::wstring, std::wstring);
    BOOL Close(VOID);
    
    VOID ListVolumes(VOID);
    BOOL Backup(std::vector<std::wstring>, std::vector<std::wstring>, std::vector<std::wstring>)
    
    const PWCHAR GetWMIError(VOID);
    VOID ShowWin32Error(PWCHAR, ...);
};

static WMI_ERROR wmiErrorTable[] = 
{
  {WBEM_S_NO_ERROR, L" The operation completed successfully."},
  {WBEM_S_FALSE, L"Either no more CIM objects are available, the number of returned CIM objects is less than the number requested, or this is the end of an enumeration.\nThis error code is returned from the IEnumWbemClassObject and IWbemWCOSmartEnum interface methods."},
  {WBEM_S_TIMEDOUT, L"The attempt to establish the connection has expired."},
  {WBEM_S_NEW_STYLE, L"The server supports ObjectArray encoding; see section 3.1.4.2.1 for details."},
  {WBEM_S_PARTIAL_RESULTS, L"The server could not return all the objects and/or properties requested."},
  {WBEM_E_FAILED, L"Call failed."},
  {WBEM_E_NOT_FOUND, L"Object cannot be found."},
  {WBEM_E_ACCESS_DENIED, L"Current user does not have permission to perform the action."},
  {WBEM_E_PROVIDER_FAILURE, L"Provider has failed at some time other than during initialization."},
  {WBEM_E_TYPE_MISMATCH, L"Type mismatch occurred."},
  {WBEM_E_OUT_OF_MEMORY, L"Not enough memory for the operation."},
  {WBEM_E_INVALID_CONTEXT, L"The IWbemContext object is not valid."},
  {WBEM_E_INVALID_PARAMETER, L"One of the parameters to the call is not correct."},
  {WBEM_E_NOT_AVAILABLE, L"Resource, typically a remote server, is not currently available."},
  {WBEM_E_CRITICAL_ERROR, L"Internal, critical, and unexpected error occurred.\nReport the error to Microsoft Technical Support."},
  {WBEM_E_INVALID_STREAM, L"One or more network packets were corrupted during a remote session."},
  {WBEM_E_NOT_SUPPORTED, L"Feature or operation is not supported."},
  {WBEM_E_INVALID_SUPERCLASS, L"Parent class specified is not valid."},
  {WBEM_E_INVALID_NAMESPACE, L"Namespace specified cannot be found."},
  {WBEM_E_INVALID_OBJECT, L"Specified instance is not valid."},
  {WBEM_E_INVALID_CLASS, L"Specified class is not valid."},
  {WBEM_E_PROVIDER_NOT_FOUND, L"Provider referenced in the schema does not have a corresponding registration."},
  {WBEM_E_INVALID_PROVIDER_REGISTRATION, L"Provider referenced in the schema has an incorrect or incomplete registration."},
  {WBEM_E_PROVIDER_LOAD_FAILURE, L"COM cannot locate a provider referenced in the schema."},
  {WBEM_E_INITIALIZATION_FAILURE, L"Component, such as a provider, failed to initialize for internal reasons."},
  {WBEM_E_TRANSPORT_FAILURE, L"Networking error that prevents normal operation has occurred."},
  {WBEM_E_INVALID_OPERATION, L"Requested operation is not valid.\nThis error usually applies to invalid attempts to delete classes or properties."},
  {WBEM_E_INVALID_QUERY, L"Query was not syntactically valid."},
  {WBEM_E_INVALID_QUERY_TYPE, L"Requested query language is not supported."},
  {WBEM_E_ALREADY_EXISTS, L"In a put operation, the wbemChangeFlagCreateOnly flag was specified, but the instance already exists."},
  {WBEM_E_OVERRIDE_NOT_ALLOWED, L"Not possible to perform the add operation on this qualifier because the owning object does not permit overrides."},
  {WBEM_E_PROPAGATED_QUALIFIER, L"User attempted to delete a qualifier that was not owned.\nThe qualifier was inherited from a parent class."},
  {WBEM_E_PROPAGATED_PROPERTY, L"User attempted to delete a property that was not owned.\nThe property was inherited from a parent class."},
  {WBEM_E_UNEXPECTED, L"Client made an unexpected and illegal sequence of calls, such as calling EndEnumeration before calling BeginEnumeration."},
  {WBEM_E_ILLEGAL_OPERATION, L"User requested an illegal operation, such as spawning a class from an instance."},
  {WBEM_E_CANNOT_BE_KEY, L"Illegal attempt to specify a key qualifier on a property that cannot be a key.\nThe keys are specified in the class definition for an object and cannot be altered on a per-instance basis."},
  {WBEM_E_INCOMPLETE_CLASS, L"Current object is not a valid class definition.\nEither it is incomplete or it has not been registered with WMI using SWbemObject.Put_."},
  {WBEM_E_INVALID_SYNTAX, L"Query is syntactically not valid."},
  {WBEM_E_NONDECORATED_OBJECT, L"Reserved for future use."},
  {WBEM_E_READ_ONLY, L"An attempt was made to modify a read-only property."},
  {WBEM_E_PROVIDER_NOT_CAPABLE, L"Provider cannot perform the requested operation.\nThis can include a query that is too complex, retrieving an instance, creating or updating a class, deleting a class, or enumerating a class."},
  {WBEM_E_CLASS_HAS_CHILDREN, L"Attempt was made to make a change that invalidates a subclass."},
  {WBEM_E_CLASS_HAS_INSTANCES, L"Attempt was made to delete or modify a class that has instances."},
  {WBEM_E_QUERY_NOT_IMPLEMENTED, L"Reserved for future use."},
  {WBEM_E_ILLEGAL_NULL, L"Value of Nothing/NULL was specified for a property that must have a value, such as one that is marked by a Key, Indexed, or Not_Null qualifier."},
  {WBEM_E_INVALID_QUALIFIER_TYPE, L"Variant value for a qualifier was provided that is not a legal qualifier type."},
  {WBEM_E_INVALID_PROPERTY_TYPE, L"CIM type specified for a property is not valid."},
  {WBEM_E_VALUE_OUT_OF_RANGE, L"Request was made with an out-of-range value or it is incompatible with the type."},
  {WBEM_E_CANNOT_BE_SINGLETON, L"Illegal attempt was made to make a class singleton, such as when the class is derived from a non-singleton class."},
  {WBEM_E_INVALID_CIM_TYPE, L"CIM type specified is not valid."},
  {WBEM_E_INVALID_METHOD, L"Requested method is not available."},
  {WBEM_E_INVALID_METHOD_PARAMETERS, L"Parameters provided for the method are not valid."},
  {WBEM_E_SYSTEM_PROPERTY, L"There was an attempt to get qualifiers on a system property."},
  {WBEM_E_INVALID_PROPERTY, L"Property type is not recognized."},
  {WBEM_E_CALL_CANCELLED, L"Asynchronous process has been canceled internally or by the user.\nNote that due to the timing and nature of the asynchronous operation, the operation may not have been truly canceled."},
  {WBEM_E_SHUTTING_DOWN, L"User has requested an operation while WMI is in the process of shutting down."},
  {WBEM_E_PROPAGATED_METHOD, L"Attempt was made to reuse an existing method name from a parent class and the signatures do not match."},
  {WBEM_E_UNSUPPORTED_PARAMETER, L"One or more parameter values, such as a query text, is too complex or unsupported.\nWMI is therefore requested to retry the operation with simpler parameters."},
  {WBEM_E_MISSING_PARAMETER_ID, L"Parameter was missing from the method call."},
  {WBEM_E_INVALID_PARAMETER_ID, L"Method parameter has an ID qualifier that is not valid."},
  {WBEM_E_NONCONSECUTIVE_PARAMETER_IDS, L"One or more of the method parameters have ID qualifiers that are out of sequence."},
  {WBEM_E_PARAMETER_ID_ON_RETVAL, L"Return value for a method has an ID qualifier."},
  {WBEM_E_INVALID_OBJECT_PATH, L"Specified object path was not valid."},
  {WBEM_E_OUT_OF_DISK_SPACE, L"Disk is out of space or the 4 GB limit on WMI repository (CIM repository) size is reached."},
  {WBEM_E_BUFFER_TOO_SMALL, L"Supplied buffer was too small to hold all of the objects in the enumerator or to read a string property."},
  {WBEM_E_UNSUPPORTED_PUT_EXTENSION, L"Provider does not support the requested put operation."},
  {WBEM_E_UNKNOWN_OBJECT_TYPE, L"Object with an incorrect type or version was encountered during marshaling."},
  {WBEM_E_UNKNOWN_PACKET_TYPE, L"Packet with an incorrect type or version was encountered during marshaling."},
  {WBEM_E_MARSHAL_VERSION_MISMATCH, L"Packet has an unsupported version."},
  {WBEM_E_MARSHAL_INVALID_SIGNATURE, L"Packet appears to be corrupt."},
  {WBEM_E_INVALID_QUALIFIER, L"Attempt was made to mismatch qualifiers, such as putting [key] on an object instead of a property."},
  {WBEM_E_INVALID_DUPLICATE_PARAMETER, L"Duplicate parameter was declared in a CIM method."},
  {WBEM_E_TOO_MUCH_DATA, L"Reserved for future use."},
  {WBEM_E_SERVER_TOO_BUSY, L"Call to IWbemObjectSink::Indicate has failed.\nThe provider can refire the event."},
  {WBEM_E_INVALID_FLAVOR, L"Specified qualifier flavor was not valid."},
  {WBEM_E_CIRCULAR_REFERENCE, L"Attempt was made to create a reference that is circular (for example, deriving a class from itself)."},
  {WBEM_E_UNSUPPORTED_CLASS_UPDATE, L"Specified class is not supported."},
  {WBEM_E_CANNOT_CHANGE_KEY_INHERITANCE, L"Attempt was made to change a key when instances or subclasses are already using the key."},
  {WBEM_E_CANNOT_CHANGE_INDEX_INHERITANCE, L"An attempt was made to change an index when instances or subclasses are already using the index."},
  {WBEM_E_TOO_MANY_PROPERTIES, L"Attempt was made to create more properties than the current version of the class supports."},
  {WBEM_E_UPDATE_TYPE_MISMATCH, L"Property was redefined with a conflicting type in a derived class."},
  {WBEM_E_UPDATE_OVERRIDE_NOT_ALLOWED, L"Attempt was made in a derived class to override a qualifier that cannot be overridden."},
  {WBEM_E_UPDATE_PROPAGATED_METHOD, L"Method was re-declared with a conflicting signature in a derived class."},
  {WBEM_E_METHOD_NOT_IMPLEMENTED, L"Attempt was made to execute a method not marked with [implemented] in any relevant class."},
  {WBEM_E_METHOD_DISABLED, L"Attempt was made to execute a method marked with [disabled]."},
  {WBEM_E_REFRESHER_BUSY, L"Refresher is busy with another operation."},
  {WBEM_E_UNPARSABLE_QUERY, L"Filtering query is syntactically not valid."},
  {WBEM_E_NOT_EVENT_CLASS, L"The FROM clause of a filtering query references a class that is not an event class (not derived from __Event)."},
  {WBEM_E_MISSING_GROUP_WITHIN, L"A GROUP BY clause was used without the corresponding GROUP WITHIN clause."},
  {WBEM_E_MISSING_AGGREGATION_LIST, L"A GROUP BY clause was used.\nAggregation on all properties is not supported."},
  {WBEM_E_PROPERTY_NOT_AN_OBJECT, L"Dot notation was used on a property that is not an embedded object."},
  {WBEM_E_AGGREGATING_BY_OBJECT, L"A GROUP BY clause references a property that is an embedded object without using dot notation."},
  {WBEM_E_UNINTERPRETABLE_PROVIDER_QUERY, L"Event provider registration query (__EventProviderRegistration) did not specify the classes for which events were provided."},
  {WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING, L"Request was made to back up or restore the repository while it was in use by WinMgmt.exe, or by the SVCHOST process that contains the WMI service."},
  {WBEM_E_QUEUE_OVERFLOW, L"Asynchronous delivery queue overflowed from the event consumer being too slow."},
  {WBEM_E_PRIVILEGE_NOT_HELD, L"Operation failed because the client did not have the necessary security privilege."},
  {WBEM_E_INVALID_OPERATOR, L"Operator is not valid for this property type."},
  {WBEM_E_LOCAL_CREDENTIALS, L"User specified a username/password/authority on a local connection.\nThe user must use a blank username/password and rely on default security."},
  {WBEM_E_CANNOT_BE_ABSTRACT, L"Class was made abstract when its parent class is not abstract."},
  {WBEM_E_AMENDED_OBJECT, L"Amended object was written without the WBEM_FLAG_USE_AMENDED_QUALIFIERS flag being specified."},
  {WBEM_E_CLIENT_TOO_SLOW, L"Client did not retrieve objects quickly enough from an enumeration.\nThis constant is returned when a client creates an enumeration object, but does not retrieve objects from the enumerator in a timely fashion, causing the enumerator's object caches to back up."},
  {WBEM_E_NULL_SECURITY_DESCRIPTOR, L"Null security descriptor was used."},
  {WBEM_E_TIMED_OUT, L"Operation timed out."},
  {WBEM_E_INVALID_ASSOCIATION, L"Association is not valid."},
  {WBEM_E_AMBIGUOUS_OPERATION, L"Operation was ambiguous."},
  {WBEM_E_QUOTA_VIOLATION, L"WMI is taking up too much memory.\nThis can be caused by low memory availability or excessive memory consumption by WMI."},
  {WBEM_E_TRANSACTION_CONFLICT, L"Operation resulted in a transaction conflict."},
  {WBEM_E_FORCED_ROLLBACK, L"Transaction forced a rollback."},
  {WBEM_E_UNSUPPORTED_LOCALE, L"Locale used in the call is not supported."},
  {WBEM_E_HANDLE_OUT_OF_DATE, L"Object handle is out-of-date."},
  {WBEM_E_CONNECTION_FAILED, L"Connection to the SQL database failed."},
  {WBEM_E_INVALID_HANDLE_REQUEST, L"Handle request was not valid."},
  {WBEM_E_PROPERTY_NAME_TOO_WIDE, L"Property name contains more than 255 characters."},
  {WBEM_E_CLASS_NAME_TOO_WIDE, L"Class name contains more than 255 characters."},
  {WBEM_E_METHOD_NAME_TOO_WIDE, L"Method name contains more than 255 characters."},
  {WBEM_E_QUALIFIER_NAME_TOO_WIDE, L"Qualifier name contains more than 255 characters."},
  {WBEM_E_RERUN_COMMAND, L"The SQL command must be rerun because there is a deadlock in SQL.\nThis can be returned only when data is being stored in an SQL database."},
  {WBEM_E_DATABASE_VER_MISMATCH, L"The database version does not match the version that the repository driver processes."},
  {WBEM_E_VETO_DELETE, L"WMI cannot execute the delete operation because the provider does not allow it."},
  {WBEM_E_VETO_PUT, L"WMI cannot execute the put operation because the provider does not allow it."},
  {WBEM_E_INVALID_LOCALE, L"Specified locale identifier was not valid for the operation."},
  {WBEM_E_PROVIDER_SUSPENDED, L"Provider is suspended."},
  {WBEM_E_SYNCHRONIZATION_REQUIRED, L"Object must be written to the WMI repository and retrieved again before the requested operation can succeed.\nThis constant is returned when an object must be committed and retrieved to see the property value."},
  {WBEM_E_NO_SCHEMA, L"Operation cannot be completed; no schema is available."},
  {WBEM_E_PROVIDER_ALREADY_REGISTERED, L"Provider cannot be registered because it is already registered."},
  {WBEM_E_PROVIDER_NOT_REGISTERED, L"Provider was not registered."},
  {WBEM_E_FATAL_TRANSPORT_ERROR, L"A fatal transport error occurred."},
  {WBEM_E_ENCRYPTED_CONNECTION_REQUIRED, L"User attempted to set a computer name or domain without an encrypted connection."},
  {WBEM_E_PROVIDER_TIMED_OUT, L"A provider failed to report results within the specified timeout."},
  {WBEM_E_NO_KEY, L"User attempted to put an instance with no defined key."},
  {WBEM_E_PROVIDER_DISABLED, L"User attempted to register a provider instance but the COM server for the provider instance was unloaded."},
  {WBEMESS_E_REGISTRATION_TOO_BROAD, L"Provider registration overlaps with the system event domain."},
  {WBEMESS_E_REGISTRATION_TOO_PRECISE, L"A WITHIN clause was not used in this query."},
  {WBEMESS_E_AUTHZ_NOT_PRIVILEGED, L"This computer does not have the necessary domain permissions to support the security functions that relate to the created subscription instance.\nContact the Domain Administrator to get this computer added to the Windows Authorization Access Group."},
  {WBEM_E_RETRY_LATER, L"Reserved for future use."},
  {WBEM_E_RESOURCE_CONTENTION, L"Reserved for future use."},
  {WBEMMOF_E_EXPECTED_QUALIFIER_NAME, L"Expected a qualifier name."},
  {WBEMMOF_E_EXPECTED_SEMI, L"Expected semicolon or '='."},
  {WBEMMOF_E_EXPECTED_OPEN_BRACE, L"Expected an opening brace."},
  {WBEMMOF_E_EXPECTED_CLOSE_BRACE, L"Missing closing brace or an illegal array element."},
  {WBEMMOF_E_EXPECTED_CLOSE_BRACKET, L"Expected a closing bracket."},
  {WBEMMOF_E_EXPECTED_CLOSE_PAREN, L"Expected closing parenthesis."},
  {WBEMMOF_E_ILLEGAL_CONSTANT_VALUE, L"Numeric value out of range or strings without quotes."},
  {WBEMMOF_E_EXPECTED_TYPE_IDENTIFIER, L"Expected a type identifier."},
  {WBEMMOF_E_EXPECTED_OPEN_PAREN, L"Expected an open parenthesis."},
  {WBEMMOF_E_UNRECOGNIZED_TOKEN, L"Unexpected token in the file."},
  {WBEMMOF_E_UNRECOGNIZED_TYPE, L"Unrecognized or unsupported type identifier."},
  {WBEMMOF_E_EXPECTED_PROPERTY_NAME, L"Expected property or method name."},
  {WBEMMOF_E_TYPEDEF_NOT_SUPPORTED, L"Typedefs and enumerated types are not supported."},
  {WBEMMOF_E_UNEXPECTED_ALIAS, L"Only a reference to a class object can have an alias value."},
  {WBEMMOF_E_UNEXPECTED_ARRAY_INIT, L"Unexpected array initialization.\nArrays must be declared with []."},
  {WBEMMOF_E_INVALID_AMENDMENT_SYNTAX, L"Namespace path syntax is not valid."},
  {WBEMMOF_E_INVALID_DUPLICATE_AMENDMENT, L"Duplicate amendment specifiers."},
  {WBEMMOF_E_INVALID_PRAGMA, L"#pragma must be followed by a valid keyword."},
  {WBEMMOF_E_INVALID_NAMESPACE_SYNTAX, L"Namespace path syntax is not valid."},
  {WBEMMOF_E_EXPECTED_CLASS_NAME, L"Unexpected character in class name must be an identifier."},
  {WBEMMOF_E_TYPE_MISMATCH, L"The value specified cannot be made into the appropriate type."},
  {WBEMMOF_E_EXPECTED_ALIAS_NAME, L"Dollar sign must be followed by an alias name as an identifier."},
  {WBEMMOF_E_INVALID_CLASS_DECLARATION, L"Class declaration is not valid."},
  {WBEMMOF_E_INVALID_INSTANCE_DECLARATION, L"The instance declaration is not valid.\nIt must start with \"instance of\""},
  {WBEMMOF_E_EXPECTED_DOLLAR, L"Expected dollar sign.\nAn alias in the form \"$name\" must follow the \"as\" keyword."},
  {WBEMMOF_E_CIMTYPE_QUALIFIER, L"\"CIMTYPE\"qualifier cannot be specified directly in a MOF file.\nUse standard type notation."},
  {WBEMMOF_E_DUPLICATE_PROPERTY, L"Duplicate property name was found in the MOF."},
  {WBEMMOF_E_INVALID_NAMESPACE_SPECIFICATION, L"Namespace syntax is not valid.\nReferences to other servers are not allowed."},
  {WBEMMOF_E_OUT_OF_RANGE, L"Value out of range."},
  {WBEMMOF_E_INVALID_FILE, L"The file is not a valid text MOF file or binary MOF file."},
  {WBEMMOF_E_ALIASES_IN_EMBEDDED, L"Embedded objects cannot be aliases."},
  {WBEMMOF_E_NULL_ARRAY_ELEM, L"NULL elements in an array are not supported."},
  {WBEMMOF_E_DUPLICATE_QUALIFIER, L"Qualifier was used more than once on the object."},
  {WBEMMOF_E_EXPECTED_FLAVOR_TYPE, L"Expected a flavor type such as ToInstance, ToSubClass, EnableOverride, or DisableOverride."},
  {WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES, L"Combining EnableOverride and DisableOverride on same qualifier is not legal."},
  {WBEMMOF_E_MULTIPLE_ALIASES, L"An alias cannot be used twice."},
  {WBEMMOF_E_INCOMPATIBLE_FLAVOR_TYPES2, L"Combining Restricted, and ToInstance or ToSubClass is not legal."},
  {WBEMMOF_E_NO_ARRAYS_RETURNED, L"Methods cannot return array values."},
  {WBEMMOF_E_MUST_BE_IN_OR_OUT, L"Arguments must have an In or Out qualifier."},
  {WBEMMOF_E_INVALID_FLAGS_SYNTAX, L"Flags syntax is not valid."},
  {WBEMMOF_E_EXPECTED_BRACE_OR_BAD_TYPE, L"The final brace and semi-colon for a class are missing."},
  {WBEMMOF_E_UNSUPPORTED_CIMV22_QUAL_VALUE, L"A CIM version 2.2 feature is not supported for a qualifier value."},
  {WBEMMOF_E_UNSUPPORTED_CIMV22_DATA_TYPE, L"The CIM version 2.2 data type is not supported."},
  {WBEMMOF_E_INVALID_DELETEINSTANCE_SYNTAX, L"The delete instance syntax is not valid.\nIt should be #pragma DeleteInstance(\"instancepath\", FAIL|NOFAIL)"},
  {WBEMMOF_E_INVALID_QUALIFIER_SYNTAX, L"The qualifier syntax is not valid.\nIt should be qualifiername:type=value,scope(class|instance), flavorname."},
  {WBEMMOF_E_QUALIFIER_USED_OUTSIDE_SCOPE, L"The qualifier is used outside of its scope."},
  {WBEMMOF_E_ERROR_CREATING_TEMP_FILE, L"Error creating temporary file.\nThe temporary file is an intermediate stage in the MOF compilation."},
  {WBEMMOF_E_ERROR_INVALID_INCLUDE_FILE, L"A file included in the MOF by the preprocessor command #include is not valid."},
  {WBEMMOF_E_INVALID_DELETECLASS_SYNTAX, L"The syntax for the preprocessor commands #pragma deleteinstance or #pragma deleteclass is not valid."}
};

#endif