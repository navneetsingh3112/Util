import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

public class Main {
    static HashMap<String, Boolean> adminRoleMap = new HashMap<>();
    static HashMap<String, String[]> roleHierarchyMap = new HashMap<>();
    static HashMap<String, String> roleAccessTypeMap = new HashMap<>();

    static HashMap<String, String> prodEmplMap = new HashMap<>();

    static HashMap<String, String> officeMap = new HashMap<>();
    static HashMap<String, String> officeHierarchyMap = new HashMap<>();
    static Map<String, TreeNode> officeHierarchyTree = new HashMap<>();

    static HashMap<String, Integer> newFileFieldPositionMap = new HashMap<>();
    static HashMap<String, String> newFileMap = new HashMap<>();
    static HashMap<String, String> hierarchyMap = new HashMap<>();
    static List<String> hierarchicalLine = new ArrayList<>();
    static String fileFieldRegex = ",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)";

    static String record;

    static String[] fieldNames = {
            "SI. No",
            "First Name",
            "Middle Name",
            "Last Name",
            "DOB",
            "Role Code",
            "Office Code",
            "Serviceable office",
            "Loan Product codes",
            "Emp ID",
            "Cost Code",
            "Department",
            "Rep Mgr ID",
            "Access Type",
            "Device Id",
            "Deviation Level",
            "Sanction Limit",
            "Mobile Number",
            "Email Id",
            "status",
            "is_deleted",
            "Remarks"
    };

    static {
        adminRoleMap.put("CRDT_STRTGY_HEAD", true);
        adminRoleMap.put("L1_SUPPORT", true);
        adminRoleMap.put("BH", true);
        adminRoleMap.put("PH", true);
        adminRoleMap.put("REP_V", true);
        adminRoleMap.put("B_ADM", true);
        adminRoleMap.put("LMS_MASTR_MAKER", true);
        adminRoleMap.put("CPU_MAKER", false);
        adminRoleMap.put("CPU_CHECKER", false);
        adminRoleMap.put("AUDIT_ADMIN", true);
        adminRoleMap.put("BTG_DIGITAL_VIEWER", true);
        adminRoleMap.put("GH", true);
        adminRoleMap.put("LMS_MASTR_CHEKR", true);
        adminRoleMap.put("UAM_MAKER", true);
        adminRoleMap.put("UAM_CHECKER", true);
        adminRoleMap.put("MASTER_MAKER", true);
        adminRoleMap.put("MASTER_CHECKER", true);
        adminRoleMap.put("CU_L5", false);
        adminRoleMap.put("RBHC", false);
        adminRoleMap.put("CU_L3", false);
        adminRoleMap.put("CRDT_STRTGY_ASSO", true);
        adminRoleMap.put("CREDIT_ANALYST", true);
        adminRoleMap.put("ZH", false);
        adminRoleMap.put("CH", false);
        adminRoleMap.put("SO", false);
        adminRoleMap.put("CPU_MAKER_FIN", true);
        adminRoleMap.put("CPU_CHECKER_FIN", true);
        adminRoleMap.put("ACM", true);
        adminRoleMap.put("CLM", true);
        adminRoleMap.put("RCM", true);
        adminRoleMap.put("FLCC_SO", false);
        adminRoleMap.put("ZCM", true);
        adminRoleMap.put("NCH", true);
        adminRoleMap.put("COL_ADMIN", true);
        adminRoleMap.put("CO", true);
        adminRoleMap.put("MIS", true);
        adminRoleMap.put("CU_L6", false);
        adminRoleMap.put("CU_L4", false);
        adminRoleMap.put("CU_L2", false);
        adminRoleMap.put("CU_L1", false);
        adminRoleMap.put("CFE", false);
        adminRoleMap.put("CRDT_STRTGY_MGR", true);
        adminRoleMap.put("NSM", true);
        adminRoleMap.put("ZHC", false);
        adminRoleMap.put("CU_L0", false);
        adminRoleMap.put("RBH", false);
        adminRoleMap.put("CRH", false);
        adminRoleMap.put("RM", false);
        adminRoleMap.put("OPS_MAKER", false);
        adminRoleMap.put("OPS_CHECKER", false);

        roleHierarchyMap.put("CRDT_STRTGY_MGR", new String[]{"CRDT_STRTGY_HEAD"});
        roleHierarchyMap.put("NSM", new String[]{"BH"});
        roleHierarchyMap.put("CU_L0", new String[]{"CU_L3"});
        roleHierarchyMap.put("CU_L1", new String[]{"CU_L3", "CU_L4"});
        roleHierarchyMap.put("CU_L2", new String[]{"CU_L3", "CU_L5"});
        roleHierarchyMap.put("CU_L3", new String[]{"CU_L5", "CU_L4"});
        roleHierarchyMap.put("CU_L4", new String[]{"CU_L5"});
        roleHierarchyMap.put("CU_L5", new String[]{"CU_L6"});
        roleHierarchyMap.put("RBH", new String[]{"ZH"});
        roleHierarchyMap.put("ZHC", new String[]{"ZH"});
        roleHierarchyMap.put("CRH", new String[]{"ZH", "RBH"});
        roleHierarchyMap.put("RM", new String[]{"CH"});
        roleHierarchyMap.put("CFE", new String[]{"CU_L1", "CU_L2", "CU_L0", "CU_L3"});
        roleHierarchyMap.put("CREDIT_ANALYST", new String[]{"CRDT_STRTGY_MGR"});
        roleHierarchyMap.put("CRDT_STRTGY_ASSO", new String[]{"CRDT_STRTGY_MGR"});
        roleHierarchyMap.put("ZH", new String[]{"NSM"});
        roleHierarchyMap.put("RBHC", new String[]{"RBH"});
        roleHierarchyMap.put("CH", new String[]{"RBH", "CRH"});
        roleHierarchyMap.put("FLCC_SO", new String[]{"RM"});
        roleHierarchyMap.put("SO", new String[]{"RM"});

        roleAccessTypeMap.put("CRDT_STRTGY_HEAD", "WEB");
        roleAccessTypeMap.put("L1_SUPPORT", "WEB");
        roleAccessTypeMap.put("BH", "WEB");
        roleAccessTypeMap.put("PH", "WEB");
        roleAccessTypeMap.put("REP_V", "WEB");
        roleAccessTypeMap.put("B_ADM", "WEB");
        roleAccessTypeMap.put("LMS_MASTR_MAKER", "WEB");
        roleAccessTypeMap.put("CPU_MAKER", "WEB");
        roleAccessTypeMap.put("CPU_CHECKER", "WEB");
        roleAccessTypeMap.put("AUDIT_ADMIN", "WEB");
        roleAccessTypeMap.put("BTG_DIGITAL_VIEWER", "WEB");
        roleAccessTypeMap.put("GH", "WEB");
        roleAccessTypeMap.put("LMS_MASTR_CHEKR", "WEB");
        roleAccessTypeMap.put("UAM_MAKER", "WEB");
        roleAccessTypeMap.put("UAM_CHECKER", "WEB");
        roleAccessTypeMap.put("MASTER_MAKER", "WEB");
        roleAccessTypeMap.put("MASTER_CHECKER", "WEB");
        roleAccessTypeMap.put("CU_L5", "WEB");
        roleAccessTypeMap.put("RBHC", "WEB");
        roleAccessTypeMap.put("CU_L3", "WEB");
        roleAccessTypeMap.put("CRDT_STRTGY_ASSO", "WEB");
        roleAccessTypeMap.put("CREDIT_ANALYST", "WEB");
        roleAccessTypeMap.put("ZH", "WEB");
        roleAccessTypeMap.put("CH", "WEB");
        roleAccessTypeMap.put("SO", "MOBILE");
        roleAccessTypeMap.put("CPU_MAKER_FIN", "WEB");
        roleAccessTypeMap.put("CPU_CHECKER_FIN", "WEB");
        roleAccessTypeMap.put("ACM", "WEB");
        roleAccessTypeMap.put("CLM", "WEB");
        roleAccessTypeMap.put("RCM", "WEB");
        roleAccessTypeMap.put("FLCC_SO", "BOTH");
        roleAccessTypeMap.put("ZCM", "WEB");
        roleAccessTypeMap.put("NCH", "WEB");
        roleAccessTypeMap.put("COL_ADMIN", "WEB");
        roleAccessTypeMap.put("CO", "MOBILE");
        roleAccessTypeMap.put("MIS", "WEB");
        roleAccessTypeMap.put("CU_L6", "WEB");
        roleAccessTypeMap.put("CU_L4", "WEB");
        roleAccessTypeMap.put("CU_L2", "WEB");
        roleAccessTypeMap.put("CU_L1", "WEB");
        roleAccessTypeMap.put("CFE", "MOBILE");
        roleAccessTypeMap.put("CRDT_STRTGY_MGR", "WEB");
        roleAccessTypeMap.put("NSM", "WEB");
        roleAccessTypeMap.put("ZHC", "WEB");
        roleAccessTypeMap.put("CU_L0", "WEB");
        roleAccessTypeMap.put("RBH", "WEB");
        roleAccessTypeMap.put("CRH", "WEB");
        roleAccessTypeMap.put("RM", "BOTH");
        roleAccessTypeMap.put("OPS_MAKER", "WEB");
        roleAccessTypeMap.put("OPS_CHECKER", "WEB");
    }

    static int totalErrorRecords = 0;
    static String systemFilePath;

    public static void main(String[] args) {
        systemFilePath = args[0];
        String officeFilePath = args[0] + "/office_prod.csv";
        String existingEmplFilePath = args[0] + "/employee_prod.csv";
        String newEmplFilePath = args[0] + "/employee_new.csv";
        for (int i = 0; i < fieldNames.length; i++) {
            newFileFieldPositionMap.put(fieldNames[i], i);
        }
        readOfficeFile(officeFilePath);
        readExistingEmplFile(existingEmplFilePath);
        try{
            readNewEmplFile(newEmplFilePath);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(record);
        }
    }

    private static void readOfficeFile(String officeFilePath) {
        File f = new File(officeFilePath);
        if (!f.exists()) {
            System.out.println("File not found: " + officeFilePath);
            return;
        }
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            int i = 0;
            while ((line = br.readLine()) != null) {
                if (i == 0) {
                    i++;
                    continue;
                }
                officeMap.put(line.split(",")[0], line);
                officeHierarchyMap.put(line.split(",")[0], line.split(",")[3]);
                i++;
            }
            officeHierarchyTree = rearrangeHierarchy(officeHierarchyMap);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void readExistingEmplFile(String existingEmplFilePath) {
        File f = new File(existingEmplFilePath);
        if (!f.exists()) {
            System.out.println("File not found: " + existingEmplFilePath);
            return;
        }
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            int i = 0;
            while ((line = br.readLine()) != null) {
                if (i == 0) {
                    i++;
                    continue;
                }
                prodEmplMap.put(line.split(fileFieldRegex)[newFileFieldPositionMap.get("Emp ID")], line);
                i++;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void readNewEmplFile(String newEmplFilePath) {
        File f = new File(newEmplFilePath);
        if (!f.exists()) {
            System.out.println("File not found: " + newEmplFilePath);
            return;
        }
        StringBuffer buf = new StringBuffer();
        int i = 0;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (i == 0) {
                    i++;
                    continue;
                }
                String[] fields = line.split(fileFieldRegex);
                String employeeId = fields[newFileFieldPositionMap.get("Emp ID")];
                String mgrId = fields[newFileFieldPositionMap.get("Rep Mgr ID")];
                newFileMap.put(employeeId, line);
                hierarchyMap.put(employeeId, mgrId);
                i++;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        Map<String, TreeNode> roots = rearrangeHierarchy(hierarchyMap);
        getArrangedHierarchy(roots);
        flushArrangedHierarchyToFile();
        for (String line : hierarchicalLine) {
            String data = validateFields(line);
            if (!data.isEmpty()) {
                buf.append(line);
                buf.append("$" + data).append("\n\n");
            }
            prodEmplMap.put(line.split(fileFieldRegex)[newFileFieldPositionMap.get("Emp ID")], line);
        }
        buf.append(newEmplFilePath + " has " + totalErrorRecords + " error records.");
        writeErrorToFile(buf.toString(), systemFilePath + "/error__" + System.currentTimeMillis() + ".csv");
    }

    private static void flushArrangedHierarchyToFile() {
        String filePath = systemFilePath + "/hierarchy__" + System.currentTimeMillis() + ".csv";
        File f = new File(filePath);
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(f))) {
            for (String line : hierarchicalLine) {
                bw.write(line);
                bw.newLine();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Map<String, TreeNode> rearrangeHierarchy(HashMap<String, String> hierarchyMap) {
        Map<String, TreeNode> nodes = new HashMap<>();
        Map<String, TreeNode> roots = new HashMap<>();

        // Create nodes for each key in the map
        for (String key : hierarchyMap.keySet()) {
            nodes.putIfAbsent(key, new TreeNode(key));
        }

        // Build the tree structure
        for (Map.Entry<String, String> entry : hierarchyMap.entrySet()) {
            String child = entry.getKey();
            String parent = entry.getValue();

            if (parent == null || parent.isEmpty() || !hierarchyMap.containsKey(parent)) {
                // If the parent is null or empty, it's a root node
                roots.put(child, nodes.get(child));
            } else {
                // Otherwise, add the child to the parent's children
                nodes.putIfAbsent(parent, new TreeNode(parent));
                nodes.get(parent).children.add(nodes.get(child));
            }
        }
        return roots;
    }

    private static void getArrangedHierarchy(Map<String, TreeNode> roots) {
        for (TreeNode root : roots.values()) {
            hierarchicalLine.add(newFileMap.get(root.value));
            getHierarchy(root);
        }
    }

    private static void getHierarchy(TreeNode root) {
        for (TreeNode child : root.children) {
            hierarchicalLine.add(newFileMap.get(child.value));
            getHierarchy(child);
        }
    }

    private static void writeErrorToFile(String data, String filePath) {
        File f = new File(filePath);
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(f))) {
            bw.write(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String validateFields(String data) {
        record = data;
        String[] fields = data.split(fileFieldRegex);
        StringBuffer error = new StringBuffer();
        for (int i = 0; i < fields.length; i++) {
            String fieldName = fieldNames[i];
            String errorMessage = validateMandatoryFields(fields[i], fieldName);
            if (errorMessage != null) {
                error.append(errorMessage);
            }
            errorMessage = validateFieldsSize(fields[i], fieldName);
            if (errorMessage != null) {
                error.append("~" + errorMessage);
            }
            errorMessage = validateFieldsRegex(fields[i], fieldName);
            if (errorMessage != null) {
                error.append("~" + errorMessage);
            }
            errorMessage = fieldsCustomValidation(fields[i], fieldName);
            if (!errorMessage.isEmpty()) {
                error.append("~" + errorMessage);
            }
        }
        return error.toString();
    }

    private static String validateMandatoryFields(String data, String fieldName) {
        String errorMessage = null;
        switch (fieldName) {
            case "First Name":
            case "Last Name":
            case "Role Code":
            case "Emp ID":
            case "Office Code":
            case "Serviceable office":
            case "Department":
            case "Access Type":
            case "Mobile Number":
            case "Email Id":
            case "status":
            case "is_deleted":
                errorMessage = validateMandatoryField(data, fieldName);
                break;
        }
        return errorMessage;
    }

    private static String validateFieldsSize(String data, String fieldName) {
        String errorMessage = null;
        switch (fieldName) {
            case "First Name":
            case "Middle Name":
            case "Last Name":
                errorMessage = validateLength(data, 1, 108, fieldName);
                break;
            case "Role Code":
            case "Emp ID":
            case "Rep Mgr ID":
                errorMessage = validateLength(data, 1, 20, fieldName);
                break;
            case "Deviation Level":
                errorMessage = validateLength(data, 1, 64, fieldName);
                break;
            case "Office Code":
                errorMessage = validateLength(data, 1, 6, fieldName);
                break;
            case "Sanction Limit":
            case "Mobile Number":
                errorMessage = validateLength(data, 1, 10, fieldName);
                break;
            case "Email Id":
                errorMessage = validateLength(data, 1, 256, fieldName);
                break;
            case "status":
                errorMessage = validateLength(data, 1, 10, fieldName);
                break;
            case "is_deleted":
                errorMessage = validateLength(data, 1, 10, fieldName);
                break;
        }
        return errorMessage;
    }

    private static String validateFieldsRegex(String data, String fieldName) {
        String errorMessage = null;
        if (data == null || data.isEmpty()) {
            return null;
        }
        switch (fieldName) {
            case "First Name":
            case "Middle Name":
                errorMessage = validateRegex("^[A-Za-z]{1}[A-Za-z\\s'.]*$", data, fieldName);
                break;
            case "Last Name":
                errorMessage = validateRegex("^[A-Za-z]{0}[A-Za-z\\s'.]*$", data, fieldName);
                break;
            case "Emp ID":
            case "Office Code":
            case "Rep Mgr ID":
                errorMessage = validateRegex("^[A-Za-z0-9]{1}[A-Za-z0-9-]*$", data, fieldName);
                break;
            case "Access Type":
                errorMessage = validateRegex("WEB|MOBILE|BOTH", data, fieldName);
                break;
            case "Deviation Level":
                errorMessage = validateRegex("^[a-zA-Z0-9]*$", data, fieldName);
                break;
            case "Sanction Limit":
                errorMessage = validateRegex("^\\d+\\.?\\d*$", data, fieldName);
                break;
            case "Mobile Number":
                errorMessage = validateRegex("^[6-9]{1}[0-9]{9}$", data, fieldName);
                break;
            case "Email Id":
                errorMessage = validateRegex("^([a-zA-Z0-9_\\-\\.']+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$", data, fieldName);
                break;
        }
        return errorMessage;
    }

    private static String fieldsCustomValidation(String data, String fieldName) {
        StringBuffer errorMessage = new StringBuffer();
        switch (fieldName) {
            case "Emp ID":
                String employeeStatus = record.split(fileFieldRegex)[newFileFieldPositionMap.get("status")];
                if (!"ACTIVE".equalsIgnoreCase(employeeStatus)) {
                    totalErrorRecords++;
                    errorMessage.append("Employee status {" + employeeStatus + "} is not active ~");
                    break;
                }
                if (prodEmplMap.containsKey(data)) {
                    errorMessage.append(fieldName + " {" + data + "} is the UPDATE case ~");
                }
                break;
            case "DOB":
                try {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
                    Date dob = sdf.parse(data);
                    long dobMillis = dob.getTime();
                    long currentMillis = System.currentTimeMillis();
                    long ageInMillis = currentMillis - dobMillis;
                    long yearsInMillis = 1000L * 60 * 60 * 24 * 365;
                    int age = (int) (ageInMillis / yearsInMillis);
                    if (age < 16 || age > 60) {
                        totalErrorRecords++;
                        errorMessage.append(fieldName + " {" + age + "} which is not between 16 and 60 years ~");
                    }
                } catch (NumberFormatException e) {
                    totalErrorRecords++;
                    errorMessage.append(fieldName + " {" + data + "} is not a valid date ~");
                } catch (ParseException e) {
                    totalErrorRecords++;
                    errorMessage.append(fieldName + " {" + data + "} is not a valid date ~");
                }
                break;
            case "Role Code":
                if (prodEmplMap.containsKey(record.split(fileFieldRegex)[newFileFieldPositionMap.get("Emp ID")])) {
                    String existingRoleCode = prodEmplMap.get(record.split(fileFieldRegex)[newFileFieldPositionMap.get("Emp ID")])
                            .split(fileFieldRegex)[newFileFieldPositionMap.get("Role Code")];
                    if (!existingRoleCode.equals(data)) {
                        totalErrorRecords++;
                        errorMessage.append(fieldName + " {" + data + "} cannot be changed from {" + existingRoleCode + "} ~");
                        break;
                    }
                }

                if (!adminRoleMap.containsKey(data)) {
                    totalErrorRecords++;
                    errorMessage.append(fieldName + " {" + data + "} is not a valid role code ~");
                    break;
                }
                boolean isAdmin = adminRoleMap.get(data);
                String reportingManagerId = getReportingManagerId();
                if (isAdmin) {
                    if (reportingManagerId != null && !reportingManagerId.isEmpty()) {
                        totalErrorRecords++;
                        errorMessage.append(fieldName + " {" + data + "} is an admin role and should not have a reporting manager ~");
                        break;
                    }
                    break;
                }
                if (roleHierarchyMap.containsKey(data)) {
                    String[] relatedRoles = roleHierarchyMap.get(data);
                    String mgrRole = null;
                    try {
                        mgrRole = getRoleOfReportingManager();
                    } catch (Exception e) {
                        totalErrorRecords++;
                        errorMessage.append("Reporting manager ADID {" + getReportingManagerId() + "} is not present in the existing employee data.Serviceable office check will not happen ~");
                        break;
                    }
                    boolean isRelatedRole = false;
                    for (String relatedRole : relatedRoles) {
                        if (relatedRole.equals(mgrRole)) {
                            isRelatedRole = true;
                            break;
                        }
                    }
                    if (!isRelatedRole) {
                        totalErrorRecords++;
                        errorMessage.append("Reporting manager role is {" + mgrRole + "} not correct. It can be one of {" + String.join(",", relatedRoles) + "} ~");
                    }
                }
                String accessType = record.split(fileFieldRegex)[newFileFieldPositionMap.get("Access Type")];
                String accessTypeForRole = roleAccessTypeMap.get(data);
                if (!accessTypeForRole.equals(accessType)) {
                    totalErrorRecords++;
                    errorMessage.append("Access type {" + accessType + "} is not correct for the role {" + data + "}. It should be {"+ accessTypeForRole+"} ~");
                }
                break;
            case "Office Code":
                String officeCodeList = getOfficeCodeList();
                String[] indOffice = officeCodeList.split(",");
                boolean isFound = false;
                for (String office : indOffice) {
                    if (office.trim().equals(data)) {
                        isFound = true;
                        break;
                    }
                }
                if (!isFound) {
                    totalErrorRecords++;
                    errorMessage.append(fieldName + " {" + data + "} is not from the Serviceable office ~");
                }
                break;
            case "Serviceable office":
                indOffice = getOfficeCodeList().split(",");
                String firstOfficeLevel = getOfficeLevelForOffice(indOffice[0].trim());
                Set<String> reportingManagerOffices;
                reportingManagerId = getReportingManagerId();
                if (firstOfficeLevel == null) {
                    totalErrorRecords++;
                    errorMessage.append(fieldName+" {" + indOffice[0].trim() + "} is not present in the production office data ~");
                    break;
                }
                try {
                    reportingManagerOffices = getReportingManagerServiceableOffices(reportingManagerId);
                } catch (Exception e) {
                    break;
                }
                for (String office : indOffice) {
                    office = office.trim();
                    String officeData = officeMap.get(office);
                    if (officeData == null) {
                        totalErrorRecords++;
                        errorMessage.append(fieldName + " {" + office + "} is not present in the production office data ~");
                        continue;
                    }
                    String officeLevel = officeData.split(",")[4];
                    if (officeLevel == null) {
                        totalErrorRecords++;
                        errorMessage.append(fieldName + " {" + office + "} is not present in the production office data ~");
                        continue;
                    }
                    if (!firstOfficeLevel.equalsIgnoreCase(officeLevel)) {
                        totalErrorRecords++;
                        errorMessage.append(fieldName + " {" + office + "} is not from the same office level {" + firstOfficeLevel + "} ~");
                        continue;
                    }
                    if (!reportingManagerOffices.contains(office)) {
                        totalErrorRecords++;

                        try {
                            List<String> reportingMgrList = new ArrayList<>();
                            reportingMgrList.add(reportingManagerId);
                            getRecursivelyAllReportingMgr(prodEmplMap.get(reportingManagerId), reportingMgrList);
                            List<String> filteredReportingMgrList = new ArrayList<>();
                            for (String reportingMgr : reportingMgrList) {
                                Set<String> reportingMgrOffices = getReportingManagerServiceableOffices(reportingMgr);
                                if (!reportingMgrOffices.contains(office)) {
                                    filteredReportingMgrList.add(reportingMgr);
                                }
                            }
                            errorMessage.append(fieldName + " {" + office + "} is not present for the reporting manager(s) {" + String.join(", ", filteredReportingMgrList) + "} ~");
                        }
                        catch(Exception e) {
                            System.out.println("Error in getting reporting manager offices "+record);
                        }
                    }
                }
                break;
            case "Email Id":
                if (data != null && !data.isEmpty()) {
                    List<String> allowedDomains = Arrays.asList("@hdfcbank.com", "@hdfcbank.co.in", "@in.hdfcbank.com");
                    String domain = data.substring(data.indexOf("@"));
                    if (!allowedDomains.contains(domain)) {
                        totalErrorRecords++;
                        errorMessage.append(fieldName + " {" + data + "} does not match the allowed domains {"
                                + String.join(", ", allowedDomains) + "} ~");
                    }
                }
                break;
            case "is_deleted":
                if ("TRUE".equalsIgnoreCase(data)) {
                    totalErrorRecords++;
                    errorMessage.append(fieldName + " {" + data + "} should not be marked as deleted ~");
                }
                break;


        }
        return errorMessage.toString();
    }

    private static String validateMandatoryField(String data, String fieldName) {
        String roleCode = record.split(fileFieldRegex)[newFileFieldPositionMap.get("Role Code")];
        if (fieldName.equals("Email Id") && roleCode.equals("SO")) {
            return null;
        }
        if (data == null || data.isEmpty()) {
            totalErrorRecords++;
            return fieldName + " is mandatory ~";
        } else {
            return null;
        }
    }

    private static String validateRegex(String regex, String data, String fieldName) {
        if (data.matches(regex)) {
            return null;
        } else {
            totalErrorRecords++;
            return fieldName + " value {" + data + "} is invalid for regex " + regex + " ~";
        }
    }

    private static String validateLength(String data, int minLength, int maxLength, String fieldName) {
        if (data.length() > maxLength && data.length() < minLength) {
            totalErrorRecords++;
            return fieldName + " value {" + data + "} is invalid for minlength {" + minLength + "} and maxlength {" + maxLength + "} ~";
        } else {
            return null;
        }
    }

    private static String getRoleOfReportingManager() {
        try {
            String reportinManagerId = getReportingManagerId();
            String mngrData = prodEmplMap.get(reportinManagerId);
            return mngrData.split(fileFieldRegex)[newFileFieldPositionMap.get("Role Code")];
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Set<String> getReportingManagerServiceableOffices(String reportingManagerId) {
        try {
            String managerData = prodEmplMap.get(reportingManagerId);
            HashSet<String> managerOffices = Arrays.stream(managerData.split(fileFieldRegex)[newFileFieldPositionMap.get("Serviceable office")].split(","))
                    .map(field -> field.replace("\"", "").trim())
                    .collect(Collectors.toCollection(HashSet::new));
            return getAllNodesForManagerOffices(managerOffices, officeHierarchyTree);
        } catch (Exception e) {
            return new HashSet<>();
            //throw new RuntimeException(e);
        }
    }

    private static String getReportingManagerId() {
        return record.split(fileFieldRegex)[newFileFieldPositionMap.get("Rep Mgr ID")];
    }

    private static String getReportingManagerIdForProdData(String data) {
        return data.split(fileFieldRegex)[newFileFieldPositionMap.get("Rep Mgr ID")];
    }


    private static String getOfficeCodeList() {
        String value = record.split(fileFieldRegex)[newFileFieldPositionMap.get("Serviceable office")];
        String field = value.trim();
        if (field.startsWith("\"") && field.endsWith("\"")) {
            field = field.substring(1, field.length() - 1).trim();
        }
        return field;
    }

    private static void getRecursivelyAllReportingMgr(String employeeData, List<String> reportingManagers) {
        String reportingManagerId = getReportingManagerIdForProdData(employeeData);
        if (reportingManagerId == null || reportingManagerId.isEmpty()) {
            return;
        }
        reportingManagers.add(reportingManagerId);
        String employeeManagerData = prodEmplMap.get(reportingManagerId);
        if (employeeManagerData == null || employeeManagerData.isEmpty()) {
            return;
        }
        getRecursivelyAllReportingMgr(employeeManagerData, reportingManagers);
    }

    public static Set<String> getAllNodesForManagerOffices(Set<String> managerOffices, Map<String, TreeNode> officeHierarchyTree) {
        Set<String> result = new HashSet<>();
        for (String office : managerOffices) {
            TreeNode node = findNodeInTree(office, officeHierarchyTree);
            if (node != null) {
                collectAllNodes(node, result);
            }
        }
        return result;
    }

    private static TreeNode findNodeInTree(String key, Map<String, TreeNode> officeHierarchyTree) {
        for (TreeNode root : officeHierarchyTree.values()) {
            TreeNode node = findNodeInSubtree(key, root);
            if (node != null) {
                return node;
            }
        }
        return null;
    }

    private static TreeNode findNodeInSubtree(String key, TreeNode node) {
        if (node.value.equals(key)) {
            return node;
        }
        for (TreeNode child : node.children) {
            TreeNode result = findNodeInSubtree(key, child);
            if (result != null) {
                return result;
            }
        }
        return null;
    }

    private static void collectAllNodes(TreeNode node, Set<String> result) {
        result.add(node.value);
        for (TreeNode child : node.children) {
            collectAllNodes(child, result);
        }
    }

    private static String getOfficeLevelForOffice(String officeCode) {
        String officeData = officeMap.get(officeCode);
        if (officeData == null) {
            return null;
        }
        return officeData.split(",")[4];
    }
}


class TreeNode {
    String value;
    List<TreeNode> children;

    TreeNode(String value) {
        this.value = value;
        this.children = new ArrayList<>();
    }
}

