#include <Python.h>

int main(void)  // no arguments allowed
{
    int rc = 0;
    Py_Initialize();
    rc = PyRun_SimpleString("import autonomous_trust as at");
    if (rc != 0)
        return rc;
    rc = PyRun_SimpleString("at.main()");
    Py_Finalize();
    return rc;
}
