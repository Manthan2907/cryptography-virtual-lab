# Access Control Fundamentals

Study and implement an access control mechanism to determine whether a subject is permitted to perform a requested operation on an object.

## Inputs
- **Access Control Model**: DAC, MAC, or RBAC.
- **Subject Identity**: Text input for the subject's name (e.g., Alice, Admin).
- **Subject Role / Clearance**: Selection of privilege tier (Guest, Student, Faculty, Administrator).
- **Target Object**: Resource identifier (e.g., Syllabus, Config file, Kernel).
- **Requested Operation**: Read, Write, Execute, Delete.

## Outputs
- **Access Decision**: Grant or Deny based on the evaluated model rules.
- **Audit Policy Log**: Persistent timestamped log of each access request, including subject, object, operation, and outcome.

## Dependencies
- Vanilla HTML5, CSS3, ES6 JavaScript.
- Uses `../../css/experiment.css` and `../../js/common.js` from the repository root.

## Test Cases
- **DAC**: Input 'Alice' requesting Read on 'public_syllabus'. Outcome: Granted.
- **MAC**: Input Role 'Student' (Clearance 2) requesting Read on 'System_Kernel.bin' (Label 4). Outcome: Denied (No Read Up).
- **RBAC**: Input Role 'Faculty' requesting Write on 'System_Config.env'. Outcome: Denied.
- **XSS Prevention**: Input `<script>alert(1)</script>` as Identity. Outcome: Securely escaped and displayed without executing.

## Known Limitations
- The simulated MAC model enforces strict equality for modifications rather than full Biba/Bell-LaPadula rules for write operations to simplify the interactive simulation.
- No backend database integration; state is ephemeral and logs reset on page reload.
