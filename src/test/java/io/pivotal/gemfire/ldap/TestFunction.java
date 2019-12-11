package io.pivotal.gemfire.ldap;

import org.apache.geode.cache.Declarable;
import org.apache.geode.cache.Region;
import org.apache.geode.cache.execute.Function;
import org.apache.geode.cache.execute.FunctionContext;
import org.apache.geode.security.ResourcePermission;

import java.util.Collection;
import java.util.Set;

public class TestFunction implements Function, Declarable {

    public static final String ID = "TestFunction";

    /**
     * Specifies whether the function sends results while executing. The method returns false if no
     * result is expected.<br>
     * <p>
     * If {@link Function#hasResult()} returns false, {@link ResultCollector#getResult()} throws
     * {@link FunctionException}.
     * </p>
     * <p>
     * If {@link Function#hasResult()} returns true, {@link ResultCollector#getResult()} blocks and
     * waits for the result of function execution
     * </p>
     *
     * @return whether this function returns a Result back to the caller.
     * @since GemFire 6.0
     */
    @Override
    public boolean hasResult() {
        return true;
    }

    /**
     * The method which contains the logic to be executed. This method should be thread safe and may
     * be invoked more than once on a given member for a single {@link Execution}. The context
     * provided to this function is the one which was built using {@linkplain Execution}. The contexts
     * can be data dependent or data-independent so user should check to see if the context provided
     * in parameter is instance of {@link RegionFunctionContext}.
     *
     * @param context as created by {@link Execution}
     * @since GemFire 6.0
     */
    @Override
    public void execute(FunctionContext context) {
        context.getResultSender().lastResult("done");
    }

    /**
     * Return a unique function identifier, used to register the function with {@link FunctionService}
     *
     * @return string identifying this function
     * @since GemFire 6.0
     */
    @Override
    public String getId() {
        return ID;
    }
}
