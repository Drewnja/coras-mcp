package coras.mcp;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.imageio.ImageIO;
import javax.swing.RepaintManager;
import javax.swing.SwingUtilities;

import org.jgraph.graph.DefaultGraphCell;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import com.vikash.firsttool.Diagram.ToolGraph;
import com.vikash.firsttool.ProfileImpl.CorasGraphCell;
import com.vikash.firsttool.ProfileImpl.ToolEdge;
import com.vikash.firsttool.ProfileImpl.ToolModel;
import com.vikash.firsttool.UI.MainFrame;

import coras.profile.dgm.ProfileToDgmMapper;
import coras.profile.model.Model;

import no.sintef.util.Pair;
import no.sintef.xml.XmlHelper;

/**
 * Command line bridge between the MCP server and the CORAS "Threat Modelling Tool".
 *
 * Everything here goes through the editor's own classes, so whatever this tool
 * reports or renders is exactly what the editor itself would do with the file.
 *
 *   validate <file.dgx>                          -> JSON report on stdout
 *   render   <file.dgx> --out <path> [options]   -> PNG/SVG of one or all diagrams
 *   open     [file.dgx]                          -> launch the editor GUI
 *
 * Only JSON is ever written to stdout; diagnostics go to stderr.
 */
public final class Bridge {

    private static final PrintStream OUT = System.out;

    public static void main(String[] args) {
        // Never let a stray library println corrupt the JSON on stdout.
        PrintStream realOut = System.out;
        System.setOut(System.err);
        try {
            if (args.length == 0) {
                fail("no command given (expected: validate | render | open | info)");
                return;
            }
            String command = args[0];
            if ("validate".equals(command)) {
                validate(realOut, args);
            } else if ("render".equals(command)) {
                render(realOut, args);
            } else if ("open".equals(command)) {
                open(realOut, args);
            } else if ("info".equals(command)) {
                info(realOut);
            } else {
                fail("unknown command: " + command);
            }
        } catch (Throwable t) {
            StringBuilder sb = new StringBuilder();
            sb.append("{\"ok\":false,\"error\":").append(Json.str(describe(t)));
            sb.append(",\"trace\":").append(Json.str(stackTrace(t))).append("}");
            realOut.println(sb);
            realOut.flush();
            System.exit(2);
        }
    }

    // ------------------------------------------------------------------ validate

    private static void validate(PrintStream out, String[] args) throws Exception {
        File file = new File(requireArg(args, 1, "validate <file.dgx>"));
        Loaded loaded = load(file);

        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true");
        sb.append(",\"file\":").append(Json.str(file.getAbsolutePath()));
        sb.append(",\"modelElements\":").append(countCells(loaded.toolModel, false));
        sb.append(",\"modelRelationships\":").append(countCells(loaded.toolModel, true));
        sb.append(",\"diagrams\":[");
        boolean first = true;
        for (ToolGraph graph : loaded.graphs) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            int vertices = 0;
            int edges = 0;
            Object[] cells = graph.getGraphLayoutCache().getVisibleCells(graph.getRoots());
            for (int i = 0; i < cells.length; i++) {
                if (cells[i] instanceof ToolEdge) {
                    edges++;
                } else if (cells[i] instanceof CorasGraphCell) {
                    vertices++;
                }
            }
            Rectangle2D bounds = graph.getCellBounds(graph.getRoots());
            sb.append("{\"name\":").append(Json.str(graph.getName()));
            sb.append(",\"nodes\":").append(vertices);
            sb.append(",\"edges\":").append(edges);
            if (bounds != null) {
                sb.append(",\"bounds\":{\"x\":").append(round(bounds.getX()))
                  .append(",\"y\":").append(round(bounds.getY()))
                  .append(",\"width\":").append(round(bounds.getWidth()))
                  .append(",\"height\":").append(round(bounds.getHeight())).append('}');
            }
            sb.append('}');
        }
        sb.append("]}");
        out.println(sb);
        out.flush();
    }

    private static int countCells(ToolModel model, boolean edges) {
        int n = 0;
        List<?> roots = model.getRoots();
        for (Object cell : roots) {
            if (edges ? (cell instanceof ToolEdge) : (cell instanceof CorasGraphCell)) {
                n++;
            }
        }
        return n;
    }

    // -------------------------------------------------------------------- render

    private static void render(PrintStream out, String[] args) throws Exception {
        File file = new File(requireArg(args, 1, "render <file.dgx> --out <path>"));
        String outPath = null;
        String format = "png";
        String which = null;
        double scale = 2.0;
        int inset = 12;

        for (int i = 2; i < args.length; i++) {
            String a = args[i];
            if ("--out".equals(a)) {
                outPath = requireArg(args, ++i, "--out <path>");
            } else if ("--format".equals(a)) {
                format = requireArg(args, ++i, "--format png|svg").toLowerCase();
            } else if ("--diagram".equals(a)) {
                which = requireArg(args, ++i, "--diagram <name|index>");
            } else if ("--scale".equals(a)) {
                scale = Double.parseDouble(requireArg(args, ++i, "--scale <number>"));
            } else if ("--inset".equals(a)) {
                inset = Integer.parseInt(requireArg(args, ++i, "--inset <pixels>"));
            } else {
                throw new IllegalArgumentException("unknown option: " + a);
            }
        }
        if (outPath == null) {
            throw new IllegalArgumentException("--out <path> is required");
        }
        if (!"png".equals(format) && !"svg".equals(format)) {
            throw new IllegalArgumentException("--format must be png or svg");
        }

        Loaded loaded = load(file);
        List<ToolGraph> selected = select(loaded.graphs, which);
        if (selected.isEmpty()) {
            throw new IllegalArgumentException("no diagram matched " + (which == null ? "(file has no diagrams)" : which));
        }

        File outFile = new File(outPath);
        // A directory, or a path with no file extension, means "one file per diagram".
        boolean multi = selected.size() > 1
                || outFile.isDirectory()
                || outFile.getName().lastIndexOf('.') <= 0;
        File dir = multi ? outFile : outFile.getParentFile();
        if (dir != null && !dir.exists()) {
            dir.mkdirs();
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true,\"images\":[");
        for (int i = 0; i < selected.size(); i++) {
            ToolGraph graph = selected.get(i);
            File target = multi
                    ? new File(outFile, safeName(graph.getName(), i) + "." + format)
                    : outFile;
            Rectangle2D bounds;
            if ("svg".equals(format)) {
                bounds = writeSvg(graph, target, scale, inset);
            } else {
                bounds = writePng(graph, target, scale, inset);
            }
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"diagram\":").append(Json.str(graph.getName()));
            sb.append(",\"path\":").append(Json.str(target.getAbsolutePath()));
            if (bounds != null) {
                sb.append(",\"width\":").append((int) Math.ceil(bounds.getWidth()))
                  .append(",\"height\":").append((int) Math.ceil(bounds.getHeight()));
            }
            sb.append('}');
        }
        sb.append("]}");
        out.println(sb);
        out.flush();
        System.exit(0);
    }

    /** Lays the graph out off-screen exactly the way the editor would draw it. */
    private static Rectangle2D prepare(ToolGraph graph, double scale, int inset) {
        graph.setScale(scale);
        graph.setGridVisible(false);
        graph.setDoubleBuffered(false);
        graph.clearSelection();
        Object[] roots = graph.getRoots();
        Rectangle2D bounds = graph.getCellBounds(roots);
        if (bounds == null) {
            return null;
        }
        Rectangle2D screen = (Rectangle2D) bounds.clone();
        graph.toScreen(screen);
        int width = (int) Math.ceil(screen.getMaxX()) + 2 * inset + 4;
        int height = (int) Math.ceil(screen.getMaxY()) + 2 * inset + 4;
        graph.setBounds(0, 0, Math.max(width, 16), Math.max(height, 16));
        graph.doLayout();
        graph.validate();
        return screen;
    }

    private static Rectangle2D writePng(ToolGraph graph, File target, double scale, int inset) throws Exception {
        Rectangle2D screen = prepare(graph, scale, inset);
        if (screen == null) {
            throw new IllegalStateException("diagram '" + graph.getName() + "' is empty");
        }
        int width = (int) Math.ceil(screen.getWidth()) + 2 * inset;
        int height = (int) Math.ceil(screen.getHeight()) + 2 * inset;
        BufferedImage image = new BufferedImage(Math.max(width, 1), Math.max(height, 1), BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, image.getWidth(), image.getHeight());
        g.translate((int) (-screen.getX() + inset), (int) (-screen.getY() + inset));
        RepaintManager rm = RepaintManager.currentManager(graph);
        boolean doubleBuffering = rm.isDoubleBufferingEnabled();
        rm.setDoubleBufferingEnabled(false);
        try {
            graph.paint(g);
        } finally {
            rm.setDoubleBufferingEnabled(doubleBuffering);
            g.dispose();
        }
        ImageIO.write(image, "png", target);
        return new Rectangle2D.Double(0, 0, image.getWidth(), image.getHeight());
    }

    /**
     * SVG export, mirroring MainEditor.writeSVG (which is private there).
     * Batik is reached reflectively so that a broken Batik never stops PNG export
     * from working.
     */
    private static Rectangle2D writeSvg(ToolGraph graph, File target, double scale, int inset) throws Exception {
        Rectangle2D screen = prepare(graph, scale, inset);
        if (screen == null) {
            throw new IllegalStateException("diagram '" + graph.getName() + "' is empty");
        }
        Document doc = XmlHelper.createDocument(null, null, "svg", null);

        Class<?> ctxClass = Class.forName("org.apache.batik.svggen.SVGGeneratorContext");
        Object ctx = ctxClass.getMethod("createDefault", Document.class).invoke(null, doc);
        ctxClass.getMethod("setEmbeddedFontsOn", boolean.class).invoke(ctx, Boolean.FALSE);
        Class<?> handlerClass = Class.forName("org.apache.batik.svggen.CachedImageHandlerBase64Encoder");
        Class<?> genericImageHandler = Class.forName("org.apache.batik.svggen.GenericImageHandler");
        Object handler = handlerClass.newInstance();
        ctxClass.getMethod("setGenericImageHandler", genericImageHandler).invoke(ctx, handler);

        Class<?> svgClass = Class.forName("org.apache.batik.svggen.SVGGraphics2D");
        Object svg = svgClass.getConstructor(ctxClass, boolean.class).newInstance(ctx, Boolean.FALSE);
        Graphics2D g = (Graphics2D) svg;
        g.translate((int) (-screen.getX() + inset), (int) (-screen.getY() + inset));

        RepaintManager rm = RepaintManager.currentManager(graph);
        boolean doubleBuffering = rm.isDoubleBufferingEnabled();
        rm.setDoubleBufferingEnabled(false);
        try {
            graph.paint(g);
        } finally {
            rm.setDoubleBufferingEnabled(doubleBuffering);
        }

        OutputStream os = new FileOutputStream(target);
        try {
            Writer writer = new OutputStreamWriter(os, "UTF-8");
            svgClass.getMethod("stream", Writer.class, boolean.class).invoke(svg, writer, Boolean.TRUE);
            writer.flush();
        } finally {
            os.close();
        }
        return new Rectangle2D.Double(0, 0,
                screen.getWidth() + 2 * inset, screen.getHeight() + 2 * inset);
    }

    private static List<ToolGraph> select(Collection<ToolGraph> graphs, String which) {
        List<ToolGraph> all = new ArrayList<ToolGraph>(graphs);
        if (which == null || "*".equals(which) || "all".equalsIgnoreCase(which)) {
            return all;
        }
        List<ToolGraph> result = new ArrayList<ToolGraph>();
        try {
            int index = Integer.parseInt(which.trim());
            if (index >= 0 && index < all.size()) {
                result.add(all.get(index));
                return result;
            }
        } catch (NumberFormatException ignored) {
            // not an index, match by name
        }
        for (ToolGraph graph : all) {
            if (which.equalsIgnoreCase(graph.getName())) {
                result.add(graph);
            }
        }
        return result;
    }

    private static String safeName(String name, int index) {
        if (name == null || name.trim().length() == 0) {
            return "diagram-" + (index + 1);
        }
        String cleaned = name.trim().replaceAll("[^A-Za-z0-9._ -]", "_").replaceAll("\\s+", "-");
        return cleaned.length() == 0 ? ("diagram-" + (index + 1)) : cleaned;
    }

    // ---------------------------------------------------------------------- open

    private static void open(PrintStream out, String[] args) throws Exception {
        final File file = args.length > 1 ? new File(args[1]) : null;
        if (file != null && !file.isFile()) {
            throw new IllegalArgumentException("no such file: " + file.getAbsolutePath());
        }
        org.apache.log4j.BasicConfigurator.configure();
        SwingUtilities.invokeAndWait(new Runnable() {
            public void run() {
                final MainFrame frame = new MainFrame();
                frame.addWindowListener(new WindowAdapter() {
                    public void windowClosing(WindowEvent e) {
                        if (frame.handleSaveChanges()) {
                            System.exit(0);
                        }
                    }
                });
                frame.setVisible(true);
                frame.toFront();
                frame.requestFocus();
                if (file != null) {
                    frame.getEditor().openfile(file);
                }
            }
        });
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true,\"opened\":")
          .append(file == null ? "null" : Json.str(file.getAbsolutePath()))
          .append('}');
        out.println(sb);
        out.flush();
    }

    // ---------------------------------------------------------------------- info

    private static void info(PrintStream out) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true");
        sb.append(",\"java\":").append(Json.str(System.getProperty("java.version")));
        sb.append(",\"vendor\":").append(Json.str(System.getProperty("java.vendor")));
        sb.append(",\"home\":").append(Json.str(System.getProperty("java.home")));
        sb.append(",\"headless\":").append(java.awt.GraphicsEnvironment.isHeadless());
        boolean display = false;
        try {
            Toolkit.getDefaultToolkit().getScreenSize();
            display = true;
        } catch (Throwable ignored) {
            display = false;
        }
        sb.append(",\"display\":").append(display);
        sb.append(",\"jaxb\":");
        try {
            Class.forName("javax.xml.bind.JAXBContext");
            sb.append("true");
        } catch (Throwable t) {
            sb.append("false");
        }
        sb.append('}');
        out.println(sb);
        out.flush();
    }

    // -------------------------------------------------------------------- shared

    private static final class Loaded {
        ToolModel toolModel;
        Collection<ToolGraph> graphs;
    }

    /** Loads a .dgx exactly the way MainEditor.openfile does. */
    private static Loaded load(File file) throws Exception {
        if (!file.isFile()) {
            throw new IllegalArgumentException("no such file: " + file.getAbsolutePath());
        }
        InputStream is = new FileInputStream(file);
        Document document;
        try {
            document = XmlHelper.parse(new InputSource(is));
        } finally {
            is.close();
        }
        String root = document.getDocumentElement().getLocalName();
        if ("java".equals(root)) {
            throw new IllegalArgumentException(
                    "this is an old version 1 (.dgm) file; open it in the editor and save it as .dgx first");
        }
        Model profileModel = Model.unmarshal(document);
        ProfileToDgmMapper mapper = new ProfileToDgmMapper();
        Pair<ToolModel, Collection<ToolGraph>> result = mapper.modelToDgm(profileModel);
        Loaded loaded = new Loaded();
        loaded.toolModel = result.getFirst();
        loaded.graphs = result.getSecond();
        // Touch every cell so that a bad model blows up here rather than in the GUI.
        for (Object cell : loaded.toolModel.getRoots()) {
            if (cell instanceof DefaultGraphCell) {
                ((DefaultGraphCell) cell).toString();
            }
        }
        return loaded;
    }

    private static String requireArg(String[] args, int index, String usage) {
        if (index >= args.length) {
            throw new IllegalArgumentException("missing argument, usage: " + usage);
        }
        return args[index];
    }

    private static void fail(String message) {
        System.err.println(message);
        OUT.println("{\"ok\":false,\"error\":" + Json.str(message) + "}");
        System.exit(2);
    }

    private static String describe(Throwable t) {
        Throwable cause = t;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        String message = cause.getMessage();
        String name = cause.getClass().getSimpleName();
        return message == null || message.length() == 0 ? name : (name + ": " + message);
    }

    private static String stackTrace(Throwable t) {
        java.io.StringWriter sw = new java.io.StringWriter();
        t.printStackTrace(new java.io.PrintWriter(sw));
        String s = sw.toString();
        return s.length() > 4000 ? s.substring(0, 4000) : s;
    }

    private static String round(double value) {
        return String.valueOf(Math.round(value * 100.0) / 100.0);
    }

    /** Minimal JSON string escaping; no dependencies. */
    static final class Json {
        static String str(String value) {
            if (value == null) {
                return "null";
            }
            StringBuilder sb = new StringBuilder(value.length() + 8);
            sb.append('"');
            for (int i = 0; i < value.length(); i++) {
                char c = value.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    case '\b': sb.append("\\b"); break;
                    case '\f': sb.append("\\f"); break;
                    default:
                        if (c < 0x20 || c > 0x7e) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                }
            }
            sb.append('"');
            return sb.toString();
        }
    }

    private Bridge() {
    }
}
